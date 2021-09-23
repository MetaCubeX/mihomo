/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package memmod

import "unsafe"

const (
	IMAGE_DOS_SIGNATURE    = 0x5A4D     // MZ
	IMAGE_OS2_SIGNATURE    = 0x454E     // NE
	IMAGE_OS2_SIGNATURE_LE = 0x454C     // LE
	IMAGE_VXD_SIGNATURE    = 0x454C     // LE
	IMAGE_NT_SIGNATURE     = 0x00004550 // PE00
)

// DOS .EXE header
type IMAGE_DOS_HEADER struct {
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for e_oeminfo)
	E_oeminfo  uint16     // OEM information; e_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   int32      // File address of new exe header
}

// File header format
type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

const (
	IMAGE_SIZEOF_FILE_HEADER = 20

	IMAGE_FILE_RELOCS_STRIPPED         = 0x0001 // Relocation info stripped from file.
	IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002 // File is executable  (i.e. no unresolved external references).
	IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004 // Line nunbers stripped from file.
	IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008 // Local symbols stripped from file.
	IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010 // Aggressively trim working set
	IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020 // App can handle >2gb addresses
	IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080 // Bytes of machine word are reversed.
	IMAGE_FILE_32BIT_MACHINE           = 0x0100 // 32 bit word machine.
	IMAGE_FILE_DEBUG_STRIPPED          = 0x0200 // Debugging info stripped from file in .DBG file
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 // If Image is on removable media, copy and run from the swap file.
	IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800 // If Image is on Net, copy and run from the swap file.
	IMAGE_FILE_SYSTEM                  = 0x1000 // System File.
	IMAGE_FILE_DLL                     = 0x2000 // File is a DLL.
	IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000 // File should only be run on a UP machine
	IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000 // Bytes of machine word are reversed.

	IMAGE_FILE_MACHINE_UNKNOWN     = 0
	IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001 // Useful for indicating we want to interact with the host and not a WoW guest.
	IMAGE_FILE_MACHINE_I386        = 0x014c // Intel 386.
	IMAGE_FILE_MACHINE_R3000       = 0x0162 // MIPS little-endian, 0x160 big-endian
	IMAGE_FILE_MACHINE_R4000       = 0x0166 // MIPS little-endian
	IMAGE_FILE_MACHINE_R10000      = 0x0168 // MIPS little-endian
	IMAGE_FILE_MACHINE_WCEMIPSV2   = 0x0169 // MIPS little-endian WCE v2
	IMAGE_FILE_MACHINE_ALPHA       = 0x0184 // Alpha_AXP
	IMAGE_FILE_MACHINE_SH3         = 0x01a2 // SH3 little-endian
	IMAGE_FILE_MACHINE_SH3DSP      = 0x01a3
	IMAGE_FILE_MACHINE_SH3E        = 0x01a4 // SH3E little-endian
	IMAGE_FILE_MACHINE_SH4         = 0x01a6 // SH4 little-endian
	IMAGE_FILE_MACHINE_SH5         = 0x01a8 // SH5
	IMAGE_FILE_MACHINE_ARM         = 0x01c0 // ARM Little-Endian
	IMAGE_FILE_MACHINE_THUMB       = 0x01c2 // ARM Thumb/Thumb-2 Little-Endian
	IMAGE_FILE_MACHINE_ARMNT       = 0x01c4 // ARM Thumb-2 Little-Endian
	IMAGE_FILE_MACHINE_AM33        = 0x01d3
	IMAGE_FILE_MACHINE_POWERPC     = 0x01F0 // IBM PowerPC Little-Endian
	IMAGE_FILE_MACHINE_POWERPCFP   = 0x01f1
	IMAGE_FILE_MACHINE_IA64        = 0x0200 // Intel 64
	IMAGE_FILE_MACHINE_MIPS16      = 0x0266 // MIPS
	IMAGE_FILE_MACHINE_ALPHA64     = 0x0284 // ALPHA64
	IMAGE_FILE_MACHINE_MIPSFPU     = 0x0366 // MIPS
	IMAGE_FILE_MACHINE_MIPSFPU16   = 0x0466 // MIPS
	IMAGE_FILE_MACHINE_AXP64       = IMAGE_FILE_MACHINE_ALPHA64
	IMAGE_FILE_MACHINE_TRICORE     = 0x0520 // Infineon
	IMAGE_FILE_MACHINE_CEF         = 0x0CEF
	IMAGE_FILE_MACHINE_EBC         = 0x0EBC // EFI Byte Code
	IMAGE_FILE_MACHINE_AMD64       = 0x8664 // AMD64 (K8)
	IMAGE_FILE_MACHINE_M32R        = 0x9041 // M32R little-endian
	IMAGE_FILE_MACHINE_ARM64       = 0xAA64 // ARM64 Little-Endian
	IMAGE_FILE_MACHINE_CEE         = 0xC0EE
)

// Directory format
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

func (ntheader *IMAGE_NT_HEADERS) Sections() []IMAGE_SECTION_HEADER {
	return (*[0xffff]IMAGE_SECTION_HEADER)(unsafe.Pointer(
		(uintptr)(unsafe.Pointer(ntheader)) +
			unsafe.Offsetof(ntheader.OptionalHeader) +
			uintptr(ntheader.FileHeader.SizeOfOptionalHeader)))[:ntheader.FileHeader.NumberOfSections]
}

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT      = 7  // (X86 usage)
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
)

const IMAGE_SIZEOF_SHORT_NAME = 8

// Section header format
type IMAGE_SECTION_HEADER struct {
	Name                         [IMAGE_SIZEOF_SHORT_NAME]byte
	physicalAddressOrVirtualSize uint32
	VirtualAddress               uint32
	SizeOfRawData                uint32
	PointerToRawData             uint32
	PointerToRelocations         uint32
	PointerToLinenumbers         uint32
	NumberOfRelocations          uint16
	NumberOfLinenumbers          uint16
	Characteristics              uint32
}

func (ishdr *IMAGE_SECTION_HEADER) PhysicalAddress() uint32 {
	return ishdr.physicalAddressOrVirtualSize
}

func (ishdr *IMAGE_SECTION_HEADER) SetPhysicalAddress(addr uint32) {
	ishdr.physicalAddressOrVirtualSize = addr
}

func (ishdr *IMAGE_SECTION_HEADER) VirtualSize() uint32 {
	return ishdr.physicalAddressOrVirtualSize
}

func (ishdr *IMAGE_SECTION_HEADER) SetVirtualSize(addr uint32) {
	ishdr.physicalAddressOrVirtualSize = addr
}

const (
	// Dll characteristics.
	IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020
	IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE          = 0x0040
	IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY       = 0x0080
	IMAGE_DLL_CHARACTERISTICS_NX_COMPAT             = 0x0100
	IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION          = 0x0200
	IMAGE_DLL_CHARACTERISTICS_NO_SEH                = 0x0400
	IMAGE_DLL_CHARACTERISTICS_NO_BIND               = 0x0800
	IMAGE_DLL_CHARACTERISTICS_APPCONTAINER          = 0x1000
	IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER            = 0x2000
	IMAGE_DLL_CHARACTERISTICS_GUARD_CF              = 0x4000
	IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
)

const (
	// Section characteristics.
	IMAGE_SCN_TYPE_REG    = 0x00000000 // Reserved.
	IMAGE_SCN_TYPE_DSECT  = 0x00000001 // Reserved.
	IMAGE_SCN_TYPE_NOLOAD = 0x00000002 // Reserved.
	IMAGE_SCN_TYPE_GROUP  = 0x00000004 // Reserved.
	IMAGE_SCN_TYPE_NO_PAD = 0x00000008 // Reserved.
	IMAGE_SCN_TYPE_COPY   = 0x00000010 // Reserved.

	IMAGE_SCN_CNT_CODE               = 0x00000020 // Section contains code.
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040 // Section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 // Section contains uninitialized data.

	IMAGE_SCN_LNK_OTHER         = 0x00000100 // Reserved.
	IMAGE_SCN_LNK_INFO          = 0x00000200 // Section contains comments or some other type of information.
	IMAGE_SCN_TYPE_OVER         = 0x00000400 // Reserved.
	IMAGE_SCN_LNK_REMOVE        = 0x00000800 // Section contents will not become part of image.
	IMAGE_SCN_LNK_COMDAT        = 0x00001000 // Section contents comdat.
	IMAGE_SCN_MEM_PROTECTED     = 0x00004000 // Obsolete.
	IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000 // Reset speculative exceptions handling bits in the TLB entries for this section.
	IMAGE_SCN_GPREL             = 0x00008000 // Section content can be accessed relative to GP
	IMAGE_SCN_MEM_FARDATA       = 0x00008000
	IMAGE_SCN_MEM_SYSHEAP       = 0x00010000 // Obsolete.
	IMAGE_SCN_MEM_PURGEABLE     = 0x00020000
	IMAGE_SCN_MEM_16BIT         = 0x00020000
	IMAGE_SCN_MEM_LOCKED        = 0x00040000
	IMAGE_SCN_MEM_PRELOAD       = 0x00080000

	IMAGE_SCN_ALIGN_1BYTES    = 0x00100000 //
	IMAGE_SCN_ALIGN_2BYTES    = 0x00200000 //
	IMAGE_SCN_ALIGN_4BYTES    = 0x00300000 //
	IMAGE_SCN_ALIGN_8BYTES    = 0x00400000 //
	IMAGE_SCN_ALIGN_16BYTES   = 0x00500000 // Default alignment if no others are specified.
	IMAGE_SCN_ALIGN_32BYTES   = 0x00600000 //
	IMAGE_SCN_ALIGN_64BYTES   = 0x00700000 //
	IMAGE_SCN_ALIGN_128BYTES  = 0x00800000 //
	IMAGE_SCN_ALIGN_256BYTES  = 0x00900000 //
	IMAGE_SCN_ALIGN_512BYTES  = 0x00A00000 //
	IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000 //
	IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000 //
	IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000 //
	IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000 //
	IMAGE_SCN_ALIGN_MASK      = 0x00F00000

	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000 // Section contains extended relocations.
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000 // Section can be discarded.
	IMAGE_SCN_MEM_NOT_CACHED  = 0x04000000 // Section is not cachable.
	IMAGE_SCN_MEM_NOT_PAGED   = 0x08000000 // Section is not pageable.
	IMAGE_SCN_MEM_SHARED      = 0x10000000 // Section is shareable.
	IMAGE_SCN_MEM_EXECUTE     = 0x20000000 // Section is executable.
	IMAGE_SCN_MEM_READ        = 0x40000000 // Section is readable.
	IMAGE_SCN_MEM_WRITE       = 0x80000000 // Section is writeable.

	// TLS Characteristic Flags
	IMAGE_SCN_SCALE_INDEX = 0x00000001 // Tls index is scaled.
)

// Based relocation format
type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

const (
	IMAGE_REL_BASED_ABSOLUTE           = 0
	IMAGE_REL_BASED_HIGH               = 1
	IMAGE_REL_BASED_LOW                = 2
	IMAGE_REL_BASED_HIGHLOW            = 3
	IMAGE_REL_BASED_HIGHADJ            = 4
	IMAGE_REL_BASED_MACHINE_SPECIFIC_5 = 5
	IMAGE_REL_BASED_RESERVED           = 6
	IMAGE_REL_BASED_MACHINE_SPECIFIC_7 = 7
	IMAGE_REL_BASED_MACHINE_SPECIFIC_8 = 8
	IMAGE_REL_BASED_MACHINE_SPECIFIC_9 = 9
	IMAGE_REL_BASED_DIR64              = 10

	IMAGE_REL_BASED_IA64_IMM64 = 9

	IMAGE_REL_BASED_MIPS_JMPADDR   = 5
	IMAGE_REL_BASED_MIPS_JMPADDR16 = 9

	IMAGE_REL_BASED_ARM_MOV32   = 5
	IMAGE_REL_BASED_THUMB_MOV32 = 7
)

// Export Format
type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint uint16
	Name [1]byte
}

func IMAGE_ORDINAL(ordinal uintptr) uintptr {
	return ordinal & 0xffff
}

func IMAGE_SNAP_BY_ORDINAL(ordinal uintptr) bool {
	return (ordinal & IMAGE_ORDINAL_FLAG) != 0
}

// Thread Local Storage
type IMAGE_TLS_DIRECTORY struct {
	StartAddressOfRawData uintptr
	EndAddressOfRawData   uintptr
	AddressOfIndex        uintptr // PDWORD
	AddressOfCallbacks    uintptr // PIMAGE_TLS_CALLBACK *;
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	characteristicsOrOriginalFirstThunk uint32 // 0 for terminating null import descriptor
	// RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	TimeDateStamp uint32 // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)
	ForwarderChain uint32 // -1 if no forwarders
	Name           uint32
	FirstThunk     uint32 // RVA to IAT (if bound this IAT has actual addresses)
}

func (imgimpdesc *IMAGE_IMPORT_DESCRIPTOR) Characteristics() uint32 {
	return imgimpdesc.characteristicsOrOriginalFirstThunk
}

func (imgimpdesc *IMAGE_IMPORT_DESCRIPTOR) OriginalFirstThunk() uint32 {
	return imgimpdesc.characteristicsOrOriginalFirstThunk
}

type IMAGE_DELAYLOAD_DESCRIPTOR struct {
	Attributes                 uint32
	DllNameRVA                 uint32
	ModuleHandleRVA            uint32
	ImportAddressTableRVA      uint32
	ImportNameTableRVA         uint32
	BoundImportAddressTableRVA uint32
	UnloadInformationTableRVA  uint32
	TimeDateStamp              uint32
}

type IMAGE_LOAD_CONFIG_CODE_INTEGRITY struct {
	Flags         uint16
	Catalog       uint16
	CatalogOffset uint32
	Reserved      uint32
}

const (
	IMAGE_GUARD_CF_INSTRUMENTED                    = 0x00000100
	IMAGE_GUARD_CFW_INSTRUMENTED                   = 0x00000200
	IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          = 0x00000400
	IMAGE_GUARD_SECURITY_COOKIE_UNUSED             = 0x00000800
	IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              = 0x00001000
	IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   = 0x00002000
	IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000
	IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       = 0x00008000
	IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          = 0x00010000
	IMAGE_GUARD_RF_INSTRUMENTED                    = 0x00020000
	IMAGE_GUARD_RF_ENABLE                          = 0x00040000
	IMAGE_GUARD_RF_STRICT                          = 0x00080000
	IMAGE_GUARD_RETPOLINE_PRESENT                  = 0x00100000
	IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT      = 0x00400000
	IMAGE_GUARD_XFG_ENABLED                        = 0x00800000
	IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        = 0xF0000000
	IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       = 28
)

type IMAGE_RUNTIME_FUNCTION_ENTRY struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnwindInfoAddress uint32
}

const (
	DLL_PROCESS_ATTACH = 1
	DLL_THREAD_ATTACH  = 2
	DLL_THREAD_DETACH  = 3
	DLL_PROCESS_DETACH = 0
)

type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}
