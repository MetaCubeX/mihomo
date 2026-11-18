package miu

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/transport/anytls/padding"

	"golang.org/x/crypto/hkdf"
)

// The initial padding scheme is derived from the auth token (sha256 of the PSK
// string), the same way the server derives it for that user, so a client and
// its server agree on the md5 in Settings and no UpdatePaddingScheme is needed.
// It has to produce exactly the text of the miu repo (miu/derived_padding.go):
// the md5 of the text is what both sides compare.
const (
	derivedSalt   = "miu/v2/padding-profile/salt"
	derivedInfo   = "miu/v2/padding-profile/v1/psk-only"
	derivedBlock  = 128
	derivedBudget = 1984
)

type derivedReader struct {
	prk     []byte
	block   []byte
	pos     int
	counter uint32
	info    string
}

func newDerivedReader(token [32]byte) (*derivedReader, error) {
	return newDerivedReaderInfo(token, derivedInfo)
}

func newDerivedReaderInfo(token [32]byte, info string) (*derivedReader, error) {
	r := &derivedReader{prk: hkdf.Extract(sha256.New, token[:], []byte(derivedSalt)), info: info}
	if err := r.expand(info); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *derivedReader) expand(info string) error {
	block := make([]byte, derivedBlock)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, r.prk, []byte(info)), block); err != nil {
		return err
	}
	r.block, r.pos = block, 0
	return nil
}

func (r *derivedReader) uint16() (uint16, error) {
	if r.pos+2 > len(r.block) {
		r.counter++
		if err := r.expand(r.info + "/counter/" + strconv.FormatUint(uint64(r.counter), 10)); err != nil {
			return 0, err
		}
	}
	x := binary.BigEndian.Uint16(r.block[r.pos:])
	r.pos += 2
	return x, nil
}

// sample returns a value in [lo, hi), rejection sampled so there is no modulo bias.
func (r *derivedReader) sample(lo, hi int) (int, error) {
	if lo >= hi {
		return 0, fmt.Errorf("miu: invalid derived range %d-%d", lo, hi)
	}
	span := hi - lo
	limit := 1<<16 - (1<<16)%span
	for {
		x, err := r.uint16()
		if err != nil {
			return 0, err
		}
		if int(x) < limit {
			return lo + int(x)%span, nil
		}
	}
}

func (r *derivedReader) span(cap, minWidth int) (int, int, error) {
	lo, err := r.sample(128, cap-(2*minWidth-1))
	if err != nil {
		return 0, 0, err
	}
	hi, err := r.sample(lo+minWidth, cap+1)
	return lo, hi, err
}

// derivedScheme is the scheme text for an auth token.
func derivedScheme(token [32]byte) (string, error) {
	r, err := newDerivedReader(token)
	if err != nil {
		return "", err
	}
	return generateScheme(r)
}

// laneInfo is the HKDF info prefix of a lane's own scheme; the lane's nonce follows it in hex.
const laneInfo = derivedInfo + "/lane/"

// laneScheme draws one lane's scheme from the same family as the PSK-derived one: the same generator and
// bounds, fed by HKDF over the authentication token with a random per-lane nonce. Each side does this on
// its own, for what it sends, and tells nobody: shaping is the sender's business and the receiver does
// not check it. Settings still carries the md5 of the PSK-derived scheme. Lanes of one user therefore do
// not share one fixed set of lengths.
func laneScheme(token [32]byte, nonce []byte) (string, error) {
	r, err := newDerivedReaderInfo(token, laneInfo+hex.EncodeToString(nonce))
	if err != nil {
		return "", err
	}
	return generateScheme(r)
}

// newLaneScheme returns a fresh lane scheme from the PSK-derived family, or base when none can be had.
func newLaneScheme(token [32]byte, base *padding.PaddingFactory) *padding.PaddingFactory {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return base
	}
	text, err := laneScheme(token, nonce[:])
	if err != nil {
		return base
	}
	if p := padding.NewPaddingFactory([]byte(text)); p != nil {
		return p
	}
	return base
}

// generateScheme is the generator of the derived schemes, reading its choices from r.
func generateScheme(r *derivedReader) (string, error) {
	count, err := r.sample(4, 10)
	if err != nil {
		return "", err
	}
	authLo, err := r.sample(24, 41)
	if err != nil {
		return "", err
	}
	authHi, err := r.sample(authLo+16, 65)
	if err != nil {
		return "", err
	}
	perPacket := (derivedBudget - authHi) / count
	lines := []string{"stop=" + strconv.Itoa(count+1), fmt.Sprintf("0=%d-%d", authLo, authHi)}
	total := authHi
	for pkt := 1; pkt <= count; pkt++ {
		double := false
		if perPacket >= 384 {
			bit, err := r.sample(0, 2)
			if err != nil {
				return "", err
			}
			double = bit == 1
		}
		if double {
			lo1, hi1, err := r.span(perPacket/2, 8)
			if err != nil {
				return "", err
			}
			lo2, hi2, err := r.span(perPacket/2, 8)
			if err != nil {
				return "", err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d,c,%d-%d", pkt, lo1, hi1, lo2, hi2))
			total += hi1 + hi2
		} else {
			lo, hi, err := r.span(perPacket, 16)
			if err != nil {
				return "", err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d", pkt, lo, hi))
			total += hi
		}
	}
	if total > derivedBudget {
		return "", fmt.Errorf("miu: derived scheme over budget: %d", total)
	}
	return strings.Join(lines, "\n"), nil
}
