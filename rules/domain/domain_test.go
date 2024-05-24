package domain

import (
	"bufio"
	"log"
	"os"
	"strings"
	"testing"
	"unicode"
)

var set *Set

func init() {
	var strs []string
	f, err := os.OpenFile("direct.txt", os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatal(err)
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
		log.Fatalln(err)
	}
	if len(strs) == 0 {
		return
	}
	set = NewSet(strs)
	log.Printf(" %d line, mem size %f MB", count, float32(set.Size())/1024/1024)
}

func TestSet_Has(t *testing.T) {
	var domains []string
	domains = append(domains, "u.jd.com")
	domains = append(domains, "oogle.com")
	domains = append(domains, "google.com")
	domains = append(domains, "1google.com")
	domains = append(domains, "1.google.com")
	domains = append(domains, "1.google.com.1")
	domains = append(domains, "com")
	domains = append(domains, "rch.google")
	domains = append(domains, ".rch.google")
	domains = append(domains, "www.youtube.com")
	domains = append(domains, "play.google.com")
	domains = append(domains, "checkip.synology.com")

	for _, v := range domains {
		t.Log(v, set.Has(v))
	}
}
