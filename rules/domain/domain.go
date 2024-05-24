package domain

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/metacubex/mihomo/log"
)

type DomainSet struct {
	File       string
	mu         sync.RWMutex
	Set        *Set
	Conditions []string
	Operator   string
	Adapter    string
	Payload    string
}

func (d *DomainSet) Init() {
	d.mu.Lock()
	defer d.mu.Unlock()
	var strs []string
	f, err := os.OpenFile(d.File, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatalln("%v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var count = 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		line = strings.TrimFunc(line, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if line == "" {
			continue
		}
		count++
		strs = append(strs, line)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalln("%v", err)
	}
	if len(strs) == 0 {
		return
	}
	d.Set = NewSet(strs)
	log.Infoln("%s loaded %d line from %s, mem size %f MB", d.Payload, count, d.File, float32(d.Set.Size())/1024/1024)
}

func (d *DomainSet) HasDomain(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.Set == nil {
		return false
	}
	return d.Set.Has(domain)
}
