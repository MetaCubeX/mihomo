package cidr

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"go4.org/netipx"
)

func (ss *IpCidrSet) WriteBin(w io.Writer) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// rr
	err = binary.Write(w, binary.BigEndian, int64(len(ss.rr)))
	if err != nil {
		return err
	}
	for _, r := range ss.rr {
		err = binary.Write(w, binary.BigEndian, r.From().As16())
		if err != nil {
			return err
		}
		err = binary.Write(w, binary.BigEndian, r.To().As16())
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadIpCidrSet(r io.Reader) (ss *IpCidrSet, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	ss = NewIpCidrSet()
	var length int64

	// rr
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, errors.New("length is invalid")
	}
	ss.rr = make([]netipx.IPRange, length)
	for i := int64(0); i < length; i++ {
		var a16 [16]byte
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		from := netip.AddrFrom16(a16).Unmap()
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		to := netip.AddrFrom16(a16).Unmap()
		ss.rr[i] = netipx.IPRangeFrom(from, to)
	}

	return ss, nil
}
