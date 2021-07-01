/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package memmod

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type addressList struct {
	next    *addressList
	address uintptr
}

func (head *addressList) free() {
	for node := head; node != nil; node = node.next {
		windows.VirtualFree(node.address, 0, windows.MEM_RELEASE)
	}
}

type Module struct {
	headers       *IMAGE_NT_HEADERS
	codeBase      uintptr
	modules       []windows.Handle
	initialized   bool
	isDLL         bool
	isRelocated   bool
	nameExports   map[string]uint16
	entry         uintptr
	blockedMemory *addressList
}

func (module *Module) headerDirectory(idx int) *IMAGE_DATA_DIRECTORY {
	return &module.headers.OptionalHeader.DataDirectory[idx]
}

func (module *Module) copySections(address uintptr, size uintptr, old_headers *IMAGE_NT_HEADERS) error {
	sections := module.headers.Sections()
	for i := range sections {
		if sections[i].SizeOfRawData == 0 {
			// Section doesn't contain data in the dll itself, but may define uninitialized data.
			sectionSize := old_headers.OptionalHeader.SectionAlignment
			if sectionSize == 0 {
				continue
			}
			dest, err := windows.VirtualAlloc(module.codeBase+uintptr(sections[i].VirtualAddress),
				uintptr(sectionSize),
				windows.MEM_COMMIT,
				windows.PAGE_READWRITE)
			if err != nil {
				return fmt.Errorf("Error allocating section: %w", err)
			}

			// Always use position from file to support alignments smaller than page size (allocation above will align to page size).
			dest = module.codeBase + uintptr(sections[i].VirtualAddress)
			// NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
			sections[i].SetPhysicalAddress((uint32)(dest & 0xffffffff))
			var dst []byte
			unsafeSlice(unsafe.Pointer(&dst), a2p(dest), int(sectionSize))
			for j := range dst {
				dst[j] = 0
			}
			continue
		}

		if size < uintptr(sections[i].PointerToRawData+sections[i].SizeOfRawData) {
			return errors.New("Incomplete section")
		}

		// Commit memory block and copy data from dll.
		dest, err := windows.VirtualAlloc(module.codeBase+uintptr(sections[i].VirtualAddress),
			uintptr(sections[i].SizeOfRawData),
			windows.MEM_COMMIT,
			windows.PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("Error allocating memory block: %w", err)
		}

		// Always use position from file to support alignments smaller than page size (allocation above will align to page size).
		memcpy(
			module.codeBase+uintptr(sections[i].VirtualAddress),
			address+uintptr(sections[i].PointerToRawData),
			uintptr(sections[i].SizeOfRawData))
		// NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
		sections[i].SetPhysicalAddress((uint32)(dest & 0xffffffff))
	}

	return nil
}

func (module *Module) realSectionSize(section *IMAGE_SECTION_HEADER) uintptr {
	size := section.SizeOfRawData
	if size != 0 {
		return uintptr(size)
	}
	if (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
		return uintptr(module.headers.OptionalHeader.SizeOfInitializedData)
	}
	if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
		return uintptr(module.headers.OptionalHeader.SizeOfUninitializedData)
	}
	return 0
}

type sectionFinalizeData struct {
	address         uintptr
	alignedAddress  uintptr
	size            uintptr
	characteristics uint32
	last            bool
}

func (module *Module) finalizeSection(sectionData *sectionFinalizeData) error {
	if sectionData.size == 0 {
		return nil
	}

	if (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
		// Section is not needed any more and can safely be freed.
		if sectionData.address == sectionData.alignedAddress &&
			(sectionData.last ||
				(sectionData.size%uintptr(module.headers.OptionalHeader.SectionAlignment)) == 0) {
			// Only allowed to decommit whole pages.
			windows.VirtualFree(sectionData.address, sectionData.size, windows.MEM_DECOMMIT)
		}
		return nil
	}

	// determine protection flags based on characteristics
	var ProtectionFlags = [8]uint32{
		windows.PAGE_NOACCESS,          // not writeable, not readable, not executable
		windows.PAGE_EXECUTE,           // not writeable, not readable, executable
		windows.PAGE_READONLY,          // not writeable, readable, not executable
		windows.PAGE_EXECUTE_READ,      // not writeable, readable, executable
		windows.PAGE_WRITECOPY,         // writeable, not readable, not executable
		windows.PAGE_EXECUTE_WRITECOPY, // writeable, not readable, executable
		windows.PAGE_READWRITE,         // writeable, readable, not executable
		windows.PAGE_EXECUTE_READWRITE, // writeable, readable, executable
	}
	protect := ProtectionFlags[sectionData.characteristics>>29]
	if (sectionData.characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0 {
		protect |= windows.PAGE_NOCACHE
	}

	// Change memory access flags.
	var oldProtect uint32
	err := windows.VirtualProtect(sectionData.address, sectionData.size, protect, &oldProtect)
	if err != nil {
		return fmt.Errorf("Error protecting memory page: %w", err)
	}

	return nil
}

func (module *Module) finalizeSections() error {
	sections := module.headers.Sections()
	imageOffset := module.headers.OptionalHeader.imageOffset()
	sectionData := sectionFinalizeData{}
	sectionData.address = uintptr(sections[0].PhysicalAddress()) | imageOffset
	sectionData.alignedAddress = alignDown(sectionData.address, uintptr(module.headers.OptionalHeader.SectionAlignment))
	sectionData.size = module.realSectionSize(&sections[0])
	sectionData.characteristics = sections[0].Characteristics

	// Loop through all sections and change access flags.
	for i := uint16(1); i < module.headers.FileHeader.NumberOfSections; i++ {
		sectionAddress := uintptr(sections[i].PhysicalAddress()) | imageOffset
		alignedAddress := alignDown(sectionAddress, uintptr(module.headers.OptionalHeader.SectionAlignment))
		sectionSize := module.realSectionSize(&sections[i])
		// Combine access flags of all sections that share a page.
		// TODO: We currently share flags of a trailing large section with the page of a first small section. This should be optimized.
		if sectionData.alignedAddress == alignedAddress || sectionData.address+sectionData.size > alignedAddress {
			// Section shares page with previous.
			if (sections[i].Characteristics&IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics&IMAGE_SCN_MEM_DISCARDABLE) == 0 {
				sectionData.characteristics = (sectionData.characteristics | sections[i].Characteristics) &^ IMAGE_SCN_MEM_DISCARDABLE
			} else {
				sectionData.characteristics |= sections[i].Characteristics
			}
			sectionData.size = sectionAddress + sectionSize - sectionData.address
			continue
		}

		err := module.finalizeSection(&sectionData)
		if err != nil {
			return fmt.Errorf("Error finalizing section: %w", err)
		}
		sectionData.address = sectionAddress
		sectionData.alignedAddress = alignedAddress
		sectionData.size = sectionSize
		sectionData.characteristics = sections[i].Characteristics
	}
	sectionData.last = true
	err := module.finalizeSection(&sectionData)
	if err != nil {
		return fmt.Errorf("Error finalizing section: %w", err)
	}
	return nil
}

func (module *Module) executeTLS() {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_TLS)
	if directory.VirtualAddress == 0 {
		return
	}

	tls := (*IMAGE_TLS_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	callback := tls.AddressOfCallbacks
	if callback != 0 {
		for {
			f := *(*uintptr)(a2p(callback))
			if f == 0 {
				break
			}
			syscall.Syscall(f, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), uintptr(0))
			callback += unsafe.Sizeof(f)
		}
	}
}

func (module *Module) performBaseRelocation(delta uintptr) (relocated bool, err error) {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
	if directory.Size == 0 {
		return delta == 0, nil
	}

	relocationHdr := (*IMAGE_BASE_RELOCATION)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	for relocationHdr.VirtualAddress > 0 {
		dest := module.codeBase + uintptr(relocationHdr.VirtualAddress)

		var relInfos []uint16
		unsafeSlice(
			unsafe.Pointer(&relInfos),
			a2p(uintptr(unsafe.Pointer(relocationHdr))+unsafe.Sizeof(*relocationHdr)),
			int((uintptr(relocationHdr.SizeOfBlock)-unsafe.Sizeof(*relocationHdr))/unsafe.Sizeof(relInfos[0])))
		for _, relInfo := range relInfos {
			// The upper 4 bits define the type of relocation.
			relType := relInfo >> 12
			// The lower 12 bits define the offset.
			relOffset := uintptr(relInfo & 0xfff)

			switch relType {
			case IMAGE_REL_BASED_ABSOLUTE:
				// Skip relocation.

			case IMAGE_REL_BASED_LOW:
				*(*uint16)(a2p(dest + relOffset)) += uint16(delta & 0xffff)
				break

			case IMAGE_REL_BASED_HIGH:
				*(*uint16)(a2p(dest + relOffset)) += uint16(uint32(delta) >> 16)
				break

			case IMAGE_REL_BASED_HIGHLOW:
				*(*uint32)(a2p(dest + relOffset)) += uint32(delta)

			case IMAGE_REL_BASED_DIR64:
				*(*uint64)(a2p(dest + relOffset)) += uint64(delta)

			case IMAGE_REL_BASED_THUMB_MOV32:
				inst := *(*uint32)(a2p(dest + relOffset))
				imm16 := ((inst << 1) & 0x0800) + ((inst << 12) & 0xf000) +
					((inst >> 20) & 0x0700) + ((inst >> 16) & 0x00ff)
				if (inst & 0x8000fbf0) != 0x0000f240 {
					return false, fmt.Errorf("Wrong Thumb2 instruction %08x, expected MOVW", inst)
				}
				imm16 += uint32(delta) & 0xffff
				hiDelta := (uint32(delta&0xffff0000) >> 16) + ((imm16 & 0xffff0000) >> 16)
				*(*uint32)(a2p(dest + relOffset)) = (inst & 0x8f00fbf0) + ((imm16 >> 1) & 0x0400) +
					((imm16 >> 12) & 0x000f) +
					((imm16 << 20) & 0x70000000) +
					((imm16 << 16) & 0xff0000)
				if hiDelta != 0 {
					inst = *(*uint32)(a2p(dest + relOffset + 4))
					imm16 = ((inst << 1) & 0x0800) + ((inst << 12) & 0xf000) +
						((inst >> 20) & 0x0700) + ((inst >> 16) & 0x00ff)
					if (inst & 0x8000fbf0) != 0x0000f2c0 {
						return false, fmt.Errorf("Wrong Thumb2 instruction %08x, expected MOVT", inst)
					}
					imm16 += hiDelta
					if imm16 > 0xffff {
						return false, fmt.Errorf("Resulting immediate value won't fit: %08x", imm16)
					}
					*(*uint32)(a2p(dest + relOffset + 4)) = (inst & 0x8f00fbf0) +
						((imm16 >> 1) & 0x0400) +
						((imm16 >> 12) & 0x000f) +
						((imm16 << 20) & 0x70000000) +
						((imm16 << 16) & 0xff0000)
				}

			default:
				return false, fmt.Errorf("Unsupported relocation: %v", relType)
			}
		}

		// Advance to next relocation block.
		relocationHdr = (*IMAGE_BASE_RELOCATION)(a2p(uintptr(unsafe.Pointer(relocationHdr)) + uintptr(relocationHdr.SizeOfBlock)))
	}
	return true, nil
}

func (module *Module) buildImportTable() error {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)
	if directory.Size == 0 {
		return nil
	}

	module.modules = make([]windows.Handle, 0, 16)
	importDesc := (*IMAGE_IMPORT_DESCRIPTOR)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	for importDesc.Name != 0 {
		handle, err := windows.LoadLibraryEx(windows.BytePtrToString((*byte)(a2p(module.codeBase+uintptr(importDesc.Name)))), 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
		if err != nil {
			return fmt.Errorf("Error loading module: %w", err)
		}
		var thunkRef, funcRef *uintptr
		if importDesc.OriginalFirstThunk() != 0 {
			thunkRef = (*uintptr)(a2p(module.codeBase + uintptr(importDesc.OriginalFirstThunk())))
			funcRef = (*uintptr)(a2p(module.codeBase + uintptr(importDesc.FirstThunk)))
		} else {
			// No hint table.
			thunkRef = (*uintptr)(a2p(module.codeBase + uintptr(importDesc.FirstThunk)))
			funcRef = (*uintptr)(a2p(module.codeBase + uintptr(importDesc.FirstThunk)))
		}
		for *thunkRef != 0 {
			if IMAGE_SNAP_BY_ORDINAL(*thunkRef) {
				*funcRef, err = windows.GetProcAddressByOrdinal(handle, IMAGE_ORDINAL(*thunkRef))
			} else {
				thunkData := (*IMAGE_IMPORT_BY_NAME)(a2p(module.codeBase + *thunkRef))
				*funcRef, err = windows.GetProcAddress(handle, windows.BytePtrToString(&thunkData.Name[0]))
			}
			if err != nil {
				windows.FreeLibrary(handle)
				return fmt.Errorf("Error getting function address: %w", err)
			}
			thunkRef = (*uintptr)(a2p(uintptr(unsafe.Pointer(thunkRef)) + unsafe.Sizeof(*thunkRef)))
			funcRef = (*uintptr)(a2p(uintptr(unsafe.Pointer(funcRef)) + unsafe.Sizeof(*funcRef)))
		}
		module.modules = append(module.modules, handle)
		importDesc = (*IMAGE_IMPORT_DESCRIPTOR)(a2p(uintptr(unsafe.Pointer(importDesc)) + unsafe.Sizeof(*importDesc)))
	}
	return nil
}

func (module *Module) buildNameExports() error {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
		return errors.New("No functions exported")
	}
	if exports.NumberOfNames == 0 {
		return errors.New("No functions exported by name")
	}
	var nameRefs []uint32
	unsafeSlice(unsafe.Pointer(&nameRefs), a2p(module.codeBase+uintptr(exports.AddressOfNames)), int(exports.NumberOfNames))
	var ordinals []uint16
	unsafeSlice(unsafe.Pointer(&ordinals), a2p(module.codeBase+uintptr(exports.AddressOfNameOrdinals)), int(exports.NumberOfNames))
	module.nameExports = make(map[string]uint16)
	for i := range nameRefs {
		nameArray := windows.BytePtrToString((*byte)(a2p(module.codeBase + uintptr(nameRefs[i]))))
		module.nameExports[nameArray] = ordinals[i]
	}
	return nil
}

// LoadLibrary loads module image to memory.
func LoadLibrary(data []byte) (module *Module, err error) {
	addr := uintptr(unsafe.Pointer(&data[0]))
	size := uintptr(len(data))
	if size < unsafe.Sizeof(IMAGE_DOS_HEADER{}) {
		return nil, errors.New("Incomplete IMAGE_DOS_HEADER")
	}
	dosHeader := (*IMAGE_DOS_HEADER)(a2p(addr))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return nil, fmt.Errorf("Not an MS-DOS binary (provided: %x, expected: %x)", dosHeader.E_magic, IMAGE_DOS_SIGNATURE)
	}
	if (size < uintptr(dosHeader.E_lfanew)+unsafe.Sizeof(IMAGE_NT_HEADERS{})) {
		return nil, errors.New("Incomplete IMAGE_NT_HEADERS")
	}
	oldHeader := (*IMAGE_NT_HEADERS)(a2p(addr + uintptr(dosHeader.E_lfanew)))
	if oldHeader.Signature != IMAGE_NT_SIGNATURE {
		return nil, fmt.Errorf("Not an NT binary (provided: %x, expected: %x)", oldHeader.Signature, IMAGE_NT_SIGNATURE)
	}
	if oldHeader.FileHeader.Machine != imageFileProcess {
		return nil, fmt.Errorf("Foreign platform (provided: %x, expected: %x)", oldHeader.FileHeader.Machine, imageFileProcess)
	}
	if (oldHeader.OptionalHeader.SectionAlignment & 1) != 0 {
		return nil, errors.New("Unaligned section")
	}
	lastSectionEnd := uintptr(0)
	sections := oldHeader.Sections()
	optionalSectionSize := oldHeader.OptionalHeader.SectionAlignment
	for i := range sections {
		var endOfSection uintptr
		if sections[i].SizeOfRawData == 0 {
			// Section without data in the DLL
			endOfSection = uintptr(sections[i].VirtualAddress) + uintptr(optionalSectionSize)
		} else {
			endOfSection = uintptr(sections[i].VirtualAddress) + uintptr(sections[i].SizeOfRawData)
		}
		if endOfSection > lastSectionEnd {
			lastSectionEnd = endOfSection
		}
	}
	alignedImageSize := alignUp(uintptr(oldHeader.OptionalHeader.SizeOfImage), uintptr(oldHeader.OptionalHeader.SectionAlignment))
	if alignedImageSize != alignUp(lastSectionEnd, uintptr(oldHeader.OptionalHeader.SectionAlignment)) {
		return nil, errors.New("Section is not page-aligned")
	}

	module = &Module{isDLL: (oldHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0}
	defer func() {
		if err != nil {
			module.Free()
			module = nil
		}
	}()

	// Reserve memory for image of library.
	// TODO: Is it correct to commit the complete memory region at once? Calling DllEntry raises an exception if we don't.
	module.codeBase, err = windows.VirtualAlloc(oldHeader.OptionalHeader.ImageBase,
		alignedImageSize,
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_READWRITE)
	if err != nil {
		// Try to allocate memory at arbitrary position.
		module.codeBase, err = windows.VirtualAlloc(0,
			alignedImageSize,
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_READWRITE)
		if err != nil {
			err = fmt.Errorf("Error allocating code: %w", err)
			return
		}
	}
	err = module.check4GBBoundaries(alignedImageSize)
	if err != nil {
		err = fmt.Errorf("Error reallocating code: %w", err)
		return
	}

	if size < uintptr(oldHeader.OptionalHeader.SizeOfHeaders) {
		err = errors.New("Incomplete headers")
		return
	}
	// Commit memory for headers.
	headers, err := windows.VirtualAlloc(module.codeBase,
		uintptr(oldHeader.OptionalHeader.SizeOfHeaders),
		windows.MEM_COMMIT,
		windows.PAGE_READWRITE)
	if err != nil {
		err = fmt.Errorf("Error allocating headers: %w", err)
		return
	}
	// Copy PE header to code.
	memcpy(headers, addr, uintptr(oldHeader.OptionalHeader.SizeOfHeaders))
	module.headers = (*IMAGE_NT_HEADERS)(a2p(headers + uintptr(dosHeader.E_lfanew)))

	// Update position.
	module.headers.OptionalHeader.ImageBase = module.codeBase

	// Copy sections from DLL file block to new memory location.
	err = module.copySections(addr, size, oldHeader)
	if err != nil {
		err = fmt.Errorf("Error copying sections: %w", err)
		return
	}

	// Adjust base address of imported data.
	locationDelta := module.headers.OptionalHeader.ImageBase - oldHeader.OptionalHeader.ImageBase
	if locationDelta != 0 {
		module.isRelocated, err = module.performBaseRelocation(locationDelta)
		if err != nil {
			err = fmt.Errorf("Error relocating module: %w", err)
			return
		}
	} else {
		module.isRelocated = true
	}

	// Load required dlls and adjust function table of imports.
	err = module.buildImportTable()
	if err != nil {
		err = fmt.Errorf("Error building import table: %w", err)
		return
	}

	// Mark memory pages depending on section headers and release sections that are marked as "discardable".
	err = module.finalizeSections()
	if err != nil {
		err = fmt.Errorf("Error finalizing sections: %w", err)
		return
	}

	// TLS callbacks are executed BEFORE the main loading.
	module.executeTLS()

	// Get entry point of loaded module.
	if module.headers.OptionalHeader.AddressOfEntryPoint != 0 {
		module.entry = module.codeBase + uintptr(module.headers.OptionalHeader.AddressOfEntryPoint)
		if module.isDLL {
			// Notify library about attaching to process.
			r0, _, _ := syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), 0)
			successful := r0 != 0
			if !successful {
				err = windows.ERROR_DLL_INIT_FAILED
				return
			}
			module.initialized = true
		}
	}

	module.buildNameExports()
	return
}

// Free releases module resources and unloads it.
func (module *Module) Free() {
	if module.initialized {
		// Notify library about detaching from process.
		syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_DETACH), 0)
		module.initialized = false
	}
	if module.modules != nil {
		// Free previously opened libraries.
		for _, handle := range module.modules {
			windows.FreeLibrary(handle)
		}
		module.modules = nil
	}
	if module.codeBase != 0 {
		windows.VirtualFree(module.codeBase, 0, windows.MEM_RELEASE)
		module.codeBase = 0
	}
	if module.blockedMemory != nil {
		module.blockedMemory.free()
		module.blockedMemory = nil
	}
}

// ProcAddressByName returns function address by exported name.
func (module *Module) ProcAddressByName(name string) (uintptr, error) {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return 0, errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if module.nameExports == nil {
		return 0, errors.New("No functions exported by name")
	}
	if idx, ok := module.nameExports[name]; ok {
		if uint32(idx) > exports.NumberOfFunctions {
			return 0, errors.New("Ordinal number too high")
		}
		// AddressOfFunctions contains the RVAs to the "real" functions.
		return module.codeBase + uintptr(*(*uint32)(a2p(module.codeBase + uintptr(exports.AddressOfFunctions) + uintptr(idx)*4))), nil
	}
	return 0, errors.New("Function not found by name")
}

// ProcAddressByOrdinal returns function address by exported ordinal.
func (module *Module) ProcAddressByOrdinal(ordinal uint16) (uintptr, error) {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return 0, errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if uint32(ordinal) < exports.Base {
		return 0, errors.New("Ordinal number too low")
	}
	idx := ordinal - uint16(exports.Base)
	if uint32(idx) > exports.NumberOfFunctions {
		return 0, errors.New("Ordinal number too high")
	}
	// AddressOfFunctions contains the RVAs to the "real" functions.
	return module.codeBase + uintptr(*(*uint32)(a2p(module.codeBase + uintptr(exports.AddressOfFunctions) + uintptr(idx)*4))), nil
}

func alignDown(value, alignment uintptr) uintptr {
	return value & ^(alignment - 1)
}

func alignUp(value, alignment uintptr) uintptr {
	return (value + alignment - 1) & ^(alignment - 1)
}

func a2p(addr uintptr) unsafe.Pointer {
	return unsafe.Pointer(addr)
}

func memcpy(dst, src, size uintptr) {
	var d, s []byte
	unsafeSlice(unsafe.Pointer(&d), a2p(dst), int(size))
	unsafeSlice(unsafe.Pointer(&s), a2p(src), int(size))
	copy(d, s)
}

// unsafeSlice updates the slice slicePtr to be a slice
// referencing the provided data with its length & capacity set to
// lenCap.
//
// TODO: when Go 1.16 or Go 1.17 is the minimum supported version,
// update callers to use unsafe.Slice instead of this.
func unsafeSlice(slicePtr, data unsafe.Pointer, lenCap int) {
	type sliceHeader struct {
		Data unsafe.Pointer
		Len  int
		Cap  int
	}
	h := (*sliceHeader)(slicePtr)
	h.Data = data
	h.Len = lenCap
	h.Cap = lenCap
}
