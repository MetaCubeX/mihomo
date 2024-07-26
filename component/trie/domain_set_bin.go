package trie

import (
	"encoding/binary"
	"errors"
	"io"
)

func (ss *DomainSet) WriteBin(w io.Writer, count int64) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// count
	err = binary.Write(w, binary.BigEndian, count)
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

func ReadDomainSetBin(r io.Reader) (ds *DomainSet, count int64, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, 0, err
	}
	if version[0] != 1 {
		return nil, 0, errors.New("version is invalid")
	}

	// count
	err = binary.Read(r, binary.BigEndian, &count)
	if err != nil {
		return nil, 0, err
	}

	ds = &DomainSet{}
	var length int64

	// leaves
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}
	if length < 1 {
		return nil, 0, errors.New("length is invalid")
	}
	ds.leaves = make([]uint64, length)
	for i := int64(0); i < length; i++ {
		err = binary.Read(r, binary.BigEndian, &ds.leaves[i])
		if err != nil {
			return nil, 0, err
		}
	}

	// labelBitmap
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}
	if length < 1 {
		return nil, 0, errors.New("length is invalid")
	}
	ds.labelBitmap = make([]uint64, length)
	for i := int64(0); i < length; i++ {
		err = binary.Read(r, binary.BigEndian, &ds.labelBitmap[i])
		if err != nil {
			return nil, 0, err
		}
	}

	// labels
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}
	if length < 1 {
		return nil, 0, errors.New("length is invalid")
	}
	ds.labels = make([]byte, length)
	_, err = io.ReadFull(r, ds.labels)
	if err != nil {
		return nil, 0, err
	}

	ds.init()
	return ds, count, nil
}
