package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
	"github.com/Dreamacro/go-shadowsocks2/core"
)

type authChain struct {
	*Base
	*recvInfo
	*authData
	randomClient   shift128PlusContext
	randomServer   shift128PlusContext
	enc            cipher.Stream
	dec            cipher.Stream
	headerSent     bool
	lastClientHash []byte
	lastServerHash []byte
	userKey        []byte
	uid            [4]byte
	salt           string
	hmac           hmacMethod
	hashDigest     hashDigestMethod
	rnd            rndMethod
	dataSizeList   []int
	dataSizeList2  []int
	chunkID        uint32
}

func init() {
	register("auth_chain_a", newAuthChainA)
}

func newAuthChainA(b *Base) Protocol {
	return &authChain{
		Base:       b,
		authData:   &authData{},
		salt:       "auth_chain_a",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainAGetRandLen,
	}
}

func (a *authChain) initForConn(iv []byte) Protocol {
	r := &authChain{
		Base: &Base{
			IV:       iv,
			Key:      a.Key,
			TCPMss:   a.TCPMss,
			Overhead: a.Overhead,
			Param:    a.Param,
		},
		recvInfo:   &recvInfo{recvID: 1, buffer: new(bytes.Buffer)},
		authData:   a.authData,
		salt:       a.salt,
		hmac:       a.hmac,
		hashDigest: a.hashDigest,
		rnd:        a.rnd,
	}
	if r.salt == "auth_chain_b" {
		initDataSize(r)
	}
	return r
}

func (a *authChain) GetProtocolOverhead() int {
	return 4
}

func (a *authChain) SetOverhead(overhead int) {
	a.Overhead = overhead
}

func (a *authChain) Decode(b []byte) ([]byte, int, error) {
	a.buffer.Reset()
	key := pool.Get(len(a.userKey) + 4)
	defer pool.Put(key)
	readSize := 0
	copy(key, a.userKey)
	for len(b) > 4 {
		binary.LittleEndian.PutUint32(key[len(a.userKey):], a.recvID)
		dataLen := (int)((uint(b[1]^a.lastServerHash[15]) << 8) + uint(b[0]^a.lastServerHash[14]))
		randLen := a.getServerRandLen(dataLen, a.Overhead)
		length := randLen + dataLen
		if length >= 4096 {
			return nil, 0, errAuthChainDataLengthError
		}
		length += 4
		if length > len(b) {
			break
		}

		hash := a.hmac(key, b[:length-2])
		if !bytes.Equal(hash[:2], b[length-2:length]) {
			return nil, 0, errAuthChainHMACError
		}
		var dataPos int
		if dataLen > 0 && randLen > 0 {
			dataPos = 2 + getRandStartPos(&a.randomServer, randLen)
		} else {
			dataPos = 2
		}
		d := pool.Get(dataLen)
		a.dec.XORKeyStream(d, b[dataPos:dataPos+dataLen])
		a.buffer.Write(d)
		pool.Put(d)
		if a.recvID == 1 {
			a.TCPMss = int(binary.LittleEndian.Uint16(a.buffer.Next(2)))
		}
		a.lastServerHash = hash
		a.recvID++
		b = b[length:]
		readSize += length
	}
	return a.buffer.Bytes(), readSize, nil
}

func (a *authChain) Encode(b []byte) ([]byte, error) {
	a.buffer.Reset()
	bSize := len(b)
	offset := 0
	if bSize > 0 && !a.headerSent {
		headSize := 1200
		if headSize > bSize {
			headSize = bSize
		}
		a.buffer.Write(a.packAuthData(b[:headSize]))
		offset += headSize
		bSize -= headSize
		a.headerSent = true
	}
	var unitSize = a.TCPMss - a.Overhead
	for bSize > unitSize {
		dataLen, randLength := a.packedDataLen(b[offset : offset+unitSize])
		d := pool.Get(dataLen)
		a.packData(d, b[offset:offset+unitSize], randLength)
		a.buffer.Write(d)
		pool.Put(d)
		bSize -= unitSize
		offset += unitSize
	}
	if bSize > 0 {
		dataLen, randLength := a.packedDataLen(b[offset:])
		d := pool.Get(dataLen)
		a.packData(d, b[offset:], randLength)
		a.buffer.Write(d)
		pool.Put(d)
	}
	return a.buffer.Bytes(), nil
}

func (a *authChain) DecodePacket(b []byte) ([]byte, int, error) {
	bSize := len(b)
	if bSize < 9 {
		return nil, 0, errAuthChainDataLengthError
	}
	h := a.hmac(a.userKey, b[:bSize-1])
	if h[0] != b[bSize-1] {
		return nil, 0, errAuthChainHMACError
	}
	hash := a.hmac(a.Key, b[bSize-8:bSize-1])
	cipherKey := a.getRC4CipherKey(hash)
	dec, _ := rc4.NewCipher(cipherKey)
	randLength := udpGetRandLen(&a.randomServer, hash)
	bSize -= 8 + randLength
	dec.XORKeyStream(b, b[:bSize])
	return b, bSize, nil
}

func (a *authChain) EncodePacket(b []byte) ([]byte, error) {
	a.initUserKeyAndID()
	authData := pool.Get(3)
	defer pool.Put(authData)
	rand.Read(authData)
	hash := a.hmac(a.Key, authData)
	uid := pool.Get(4)
	defer pool.Put(uid)
	for i := 0; i < 4; i++ {
		uid[i] = a.uid[i] ^ hash[i]
	}

	cipherKey := a.getRC4CipherKey(hash)
	enc, _ := rc4.NewCipher(cipherKey)
	var buf bytes.Buffer
	enc.XORKeyStream(b, b)
	buf.Write(b)

	randLength := udpGetRandLen(&a.randomClient, hash)
	randBytes := pool.Get(randLength)
	defer pool.Put(randBytes)
	buf.Write(randBytes)

	buf.Write(authData)
	buf.Write(uid)

	h := a.hmac(a.userKey, buf.Bytes())
	buf.Write(h[:1])
	return buf.Bytes(), nil
}

func (a *authChain) getRC4CipherKey(hash []byte) []byte {
	base64UserKey := base64.StdEncoding.EncodeToString(a.userKey)
	return a.calcRC4CipherKey(hash, base64UserKey)
}

func (a *authChain) calcRC4CipherKey(hash []byte, base64UserKey string) []byte {
	password := pool.Get(len(base64UserKey) + base64.StdEncoding.EncodedLen(16))
	defer pool.Put(password)
	copy(password, base64UserKey)
	base64.StdEncoding.Encode(password[len(base64UserKey):], hash[:16])
	return core.Kdf(string(password), 16)
}

func (a *authChain) initUserKeyAndID() {
	if a.userKey == nil {
		params := strings.Split(a.Param, ":")
		if len(params) >= 2 {
			if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
				binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
				a.userKey = []byte(params[1])[:len(a.userKey)]
			}
		}

		if a.userKey == nil {
			rand.Read(a.uid[:])
			a.userKey = make([]byte, len(a.Key))
			copy(a.userKey, a.Key)
		}
	}
}

func (a *authChain) getClientRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChain) getServerRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChain) packedDataLen(data []byte) (chunkLength, randLength int) {
	dataLength := len(data)
	randLength = a.getClientRandLen(dataLength, a.Overhead)
	chunkLength = randLength + dataLength + 2 + 2
	return
}

func (a *authChain) packData(outData []byte, data []byte, randLength int) {
	dataLength := len(data)
	outLength := randLength + dataLength + 2
	outData[0] = byte(dataLength) ^ a.lastClientHash[14]
	outData[1] = byte(dataLength>>8) ^ a.lastClientHash[15]

	{
		if dataLength > 0 {
			randPart1Length := getRandStartPos(&a.randomClient, randLength)
			rand.Read(outData[2 : 2+randPart1Length])
			a.enc.XORKeyStream(outData[2+randPart1Length:], data)
			rand.Read(outData[2+randPart1Length+dataLength : outLength])
		} else {
			rand.Read(outData[2 : 2+randLength])
		}
	}

	userKeyLen := uint8(len(a.userKey))
	key := pool.Get(int(userKeyLen + 4))
	defer pool.Put(key)
	copy(key, a.userKey)
	a.chunkID++
	binary.LittleEndian.PutUint32(key[userKeyLen:], a.chunkID)
	a.lastClientHash = a.hmac(key, outData[:outLength])
	copy(outData[outLength:], a.lastClientHash[:2])
	return
}

const authHeadLength = 4 + 8 + 4 + 16 + 4

func (a *authChain) packAuthData(data []byte) (outData []byte) {
	outData = make([]byte, authHeadLength, authHeadLength+1500)
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.connectionID++
	if a.connectionID > 0xFF000000 {
		rand.Read(a.clientID)
		b := make([]byte, 4)
		rand.Read(b)
		a.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	var key = make([]byte, len(a.IV)+len(a.Key))
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	encrypt := make([]byte, 20)
	t := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(t))
	copy(encrypt[4:8], a.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(a.Overhead))
	binary.LittleEndian.PutUint16(encrypt[14:], 0)

	// first 12 bytes
	{
		rand.Read(outData[:4])
		a.lastClientHash = a.hmac(key, outData[:4])
		copy(outData[4:], a.lastClientHash[:8])
	}
	var base64UserKey string
	// uid & 16 bytes auth data
	{
		a.initUserKeyAndID()
		uid := make([]byte, 4)
		for i := 0; i < 4; i++ {
			uid[i] = a.uid[i] ^ a.lastClientHash[8+i]
		}
		base64UserKey = base64.StdEncoding.EncodeToString(a.userKey)
		aesCipherKey := core.Kdf(base64UserKey+a.salt, 16)
		block, err := aes.NewCipher(aesCipherKey)
		if err != nil {
			return
		}
		encryptData := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encryptData, encrypt[:16])
		copy(encrypt[:4], uid[:])
		copy(encrypt[4:4+16], encryptData)
	}
	// final HMAC
	{
		a.lastServerHash = a.hmac(a.userKey, encrypt[:20])

		copy(outData[12:], encrypt)
		copy(outData[12+20:], a.lastServerHash[:4])
	}

	// init cipher
	cipherKey := a.calcRC4CipherKey(a.lastClientHash, base64UserKey)
	a.enc, _ = rc4.NewCipher(cipherKey)
	a.dec, _ = rc4.NewCipher(cipherKey)

	// data
	chunkLength, randLength := a.packedDataLen(data)
	if chunkLength <= 1500 {
		outData = outData[:authHeadLength+chunkLength]
	} else {
		newOutData := make([]byte, authHeadLength+chunkLength)
		copy(newOutData, outData[:authHeadLength])
		outData = newOutData
	}
	a.packData(outData[authHeadLength:], data, randLength)
	return
}

func getRandStartPos(random *shift128PlusContext, randLength int) int {
	if randLength > 0 {
		return int(random.Next() % 8589934609 % uint64(randLength))
	}
	return 0
}

func authChainAGetRandLen(dataLength int, random *shift128PlusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func udpGetRandLen(random *shift128PlusContext, lastHash []byte) int {
	random.InitFromBin(lastHash[:16])
	return int(random.Next() % 127)
}

type shift128PlusContext struct {
	v [2]uint64
}

func (ctx *shift128PlusContext) InitFromBin(bin []byte) {
	var fillBin [16]byte
	copy(fillBin[:], bin)

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])
}

func (ctx *shift128PlusContext) InitFromBinDatalen(bin []byte, datalen int) {
	var fillBin [16]byte
	copy(fillBin[:], bin)
	binary.LittleEndian.PutUint16(fillBin[:2], uint16(datalen))

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])

	for i := 0; i < 4; i++ {
		ctx.Next()
	}
}

func (ctx *shift128PlusContext) Next() uint64 {
	x := ctx.v[0]
	y := ctx.v[1]
	ctx.v[0] = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	ctx.v[1] = x
	return x + y
}
