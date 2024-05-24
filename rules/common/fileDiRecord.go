package common

import (
	"bufio"
	"context"
	"github.com/metacubex/mihomo/component/mmdb"
	"net"
	"os"
	P "path"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/domain"
)

var (
	setsRecord    map[string]*domain.DomainSet = make(map[string]*domain.DomainSet)
	fdrdoonce     sync.Once
	domainchannel chan *recordedDomain
)

type recordedDomain struct {
	domain  string
	zoneset *domain.DomainSet
}

type FileDIRecord struct {
	adapter    string
	payload    string
	conditions []string
	operator   string
}

func (f *FileDIRecord) RuleType() C.RuleType {
	return C.RECORD
}

func (f *FileDIRecord) Match(metadata *C.Metadata) (bool, string) {
	host := metadata.Host
	if host == "" {
		return false, ""
	}
	for _, zoneset := range setsRecord {
		if zoneset.HasDomain(host) {
			metadata.HitRule = zoneset.Payload
			return true, zoneset.Adapter
		}
	}
	if !metadata.DstIP.IsValid() {
		ip, err := resolver.ResolveIP(context.TODO(), host)
		if err != nil {
			//log.Warnln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			return false, f.adapter
		} else {
			metadata.DstIP = ip
		}
	}
	for _, zoneset := range setsRecord {
		if matchISO(metadata.DstIP.AsSlice(), host, zoneset, metadata) {
			return true, zoneset.Adapter
		}
	}
	return false, f.adapter
}

func (f *FileDIRecord) Adapter() string {
	return f.adapter
}

func (f *FileDIRecord) Payload() string {
	return f.payload
}

func (f *FileDIRecord) ShouldResolveIP() bool {
	return false
}

func (f *FileDIRecord) ShouldFindProcess() bool {
	return false
}

func NewFileDIRecord(payload, adapter string, params []string) *FileDIRecord {
	fdrdoonce.Do(func() {
		domainchannel = make(chan *recordedDomain, 100)
		go func() {
			for rd := range domainchannel {
				readAndWrite(rd.zoneset.File, rd.domain)
				rd.zoneset.Init()
			}
		}()
	})
	groups := make([][]string, 0)
	var count = 0
	for {
		group := make([]string, 0)
		if count == 0 {
			group = append(group, payload)
			group = append(group, adapter)
		}
		count++
		var idx = slices.Index(params, "@")
		if idx > -1 {
			group = append(group, params[0:idx]...)
			groups = append(groups, group)
			params = params[idx+1:]
		} else {
			group = append(group, params[:]...)
			groups = append(groups, group)
			break
		}
	}
	for _, group := range groups {
		log.Infoln("%v", group)
		domainSet := &domain.DomainSet{
			File:       P.Join(C.Path.HomeDir(), group[2]),
			Conditions: group[4:],
			Operator:   group[3],
			Adapter:    group[1],
			Payload:    group[0],
		}
		domainSet.Init()
		setsRecord[domainSet.Payload] = domainSet
	}

	return &FileDIRecord{
		adapter: "unknown",
		payload: "unknown",
	}
}

func matchISO(ipAddress net.IP, host string, domainSet *domain.DomainSet, metadata *C.Metadata) bool {
	if !metadata.GeoedIp() {
		metadata.DstGeoIP = mmdb.IPInstance().LookupCode(ipAddress)
		if !metadata.GeoedIp() {
			return false
		}
	}
	iso := metadata.DstGeoIP[0]
	var match bool
	if domainSet.Operator == "and" {
		match = true
		for _, cond := range domainSet.Conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = strings.EqualFold(iso, cond)
				match = !match
			} else {
				match = strings.EqualFold(iso, cond)
			}
			if !match {
				return false
			}
		}
	} else if domainSet.Operator == "or" {
		match = false
		for _, cond := range domainSet.Conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = strings.EqualFold(iso, cond)
				match = !match
			} else {
				match = strings.EqualFold(iso, cond)
			}
			if match {
				break
			}
		}
	} else {
		return false
	}

	if match {
		log.Warnln("add %s into %s, ip %s ios %s", host, domainSet.File, ipAddress, iso)
		domainchannel <- &recordedDomain{
			domain:  host,
			zoneset: domainSet,
		}
		return true
	}
	return false
}

func readAndWrite(file, domain string) {
	var strs = make([]string, 0, 1000)
	var seen = make(map[string]bool, 1000)
	if _, err := os.Stat(file); err == nil {
		f, err := os.OpenFile(file, os.O_RDONLY, os.ModePerm)
		if err != nil {
			log.Errorln("%v", err)
			return
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			line = strings.TrimFunc(line, func(r rune) bool {
				return !unicode.IsGraphic(r)
			})
			if line == "" {
				continue
			}
			if seen[line] {
				continue
			}
			strs = append(strs, line)
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return
		}
		f.Close()
	}
	strs = append(strs, domain)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return
	}
	for _, v := range strs {
		f.WriteString(v + "\n")
	}
	f.Close()
}
