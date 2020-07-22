package protocol

import (
	"sort"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("auth_chain_b", newAuthChainB)
}

func newAuthChainB(b *Base) Protocol {
	return &authChain{
		Base:       b,
		authData:   &authData{},
		salt:       "auth_chain_b",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainBGetRandLen,
	}
}

func initDataSize(r *authChain) {
	random := &r.randomServer
	random.InitFromBin(r.Key)
	len := random.Next()%8 + 4
	r.dataSizeList = make([]int, len)
	for i := 0; i < int(len); i++ {
		r.dataSizeList[i] = int(random.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(r.dataSizeList)

	len = random.Next()%16 + 8
	r.dataSizeList2 = make([]int, len)
	for i := 0; i < int(len); i++ {
		r.dataSizeList2[i] = int(random.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(r.dataSizeList2)
}

func authChainBGetRandLen(dataLength int, random *shift128PlusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	pos := sort.Search(len(dataSizeList), func(i int) bool { return dataSizeList[i] > dataLength+overhead })
	finalPos := uint64(pos) + random.Next()%uint64(len(dataSizeList))
	if finalPos < uint64(len(dataSizeList)) {
		return dataSizeList[finalPos] - dataLength - overhead
	}

	pos = sort.Search(len(dataSizeList2), func(i int) bool { return dataSizeList2[i] > dataLength+overhead })
	finalPos = uint64(pos) + random.Next()%uint64(len(dataSizeList2))
	if finalPos < uint64(len(dataSizeList2)) {
		return dataSizeList2[finalPos] - dataLength - overhead
	}
	if finalPos < uint64(pos+len(dataSizeList2)-1) {
		return 0
	}

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
