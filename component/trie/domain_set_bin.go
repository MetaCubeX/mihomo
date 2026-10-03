package trie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

func (ss *DomainSet) WriteBin(w io.Writer) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// leaves
	err = binary.Write(w, binary.BigEndian, int64(len(ss.leaves)))
	if err != nil {
		return err
	}
	for _, d := range ss.leaves {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labelBitmap
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labelBitmap)))
	if err != nil {
		return err
	}
	for _, d := range ss.labelBitmap {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labels
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labels)))
	if err != nil {
		return err
	}
	_, err = w.Write(ss.labels)
	if err != nil {
		return err
	}

	return nil
}

func ReadDomainSetBin(r io.Reader) (ds *DomainSet, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	ds = &DomainSet{}
	var length int64

	// leaves
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, errors.New("length is invalid")
	}
	// length is untrusted; grow via append so a crafted huge length hits EOF while reading the
	// elements instead of OOMing the process on the allocation.
	leavesCap := length
	if leavesCap > 64 {
		leavesCap = 64
	}
	ds.leaves = make([]uint64, 0, leavesCap)
	for i := int64(0); i < length; i++ {
		var value uint64
		if err = binary.Read(r, binary.BigEndian, &value); err != nil {
			return nil, err
		}
		ds.leaves = append(ds.leaves, value)
	}

	// labelBitmap
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, errors.New("length is invalid")
	}
	labelBitmapCap := length
	if labelBitmapCap > 64 {
		labelBitmapCap = 64
	}
	ds.labelBitmap = make([]uint64, 0, labelBitmapCap)
	for i := int64(0); i < length; i++ {
		var value uint64
		if err = binary.Read(r, binary.BigEndian, &value); err != nil {
			return nil, err
		}
		ds.labelBitmap = append(ds.labelBitmap, value)
	}

	// labels
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, errors.New("length is invalid")
	}
	// length is untrusted; read via io.CopyN so the buffer grows only as bytes actually arrive,
	// instead of pre-allocating make([]byte, length) and OOMing on a crafted length.
	var labelsBuf bytes.Buffer
	_, err = io.CopyN(&labelsBuf, r, length)
	if err != nil {
		return nil, err
	}
	if int64(labelsBuf.Len()) != length {
		return nil, io.ErrUnexpectedEOF
	}
	ds.labels = labelsBuf.Bytes()

	ds.init()
	return ds, nil
}
