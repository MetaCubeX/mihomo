package hosts

// this file copy and modify from golang's std net/hosts.go

import (
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

var hostsFilePath = "/etc/hosts"

const cacheMaxAge = 5 * time.Second

func parseLiteralIP(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return ip.String()
}

type byName struct {
	addrs         []string
	canonicalName string
}

// hosts contains known host entries.
var hosts struct {
	sync.Mutex

	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName map[string]byName

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string

	expire time.Time
	path   string
	mtime  time.Time
	size   int64
}

func readHosts() {
	now := time.Now()
	hp := hostsFilePath

	if now.Before(hosts.expire) && hosts.path == hp && len(hosts.byName) > 0 {
		return
	}
	mtime, size, err := stat(hp)
	if err == nil && hosts.path == hp && hosts.mtime.Equal(mtime) && hosts.size == size {
		hosts.expire = now.Add(cacheMaxAge)
		return
	}

	hs := make(map[string]byName)
	is := make(map[string][]string)

	file, err := open(hp)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return
		}
	}

	if file != nil {
		defer file.close()
		for line, ok := file.readLine(); ok; line, ok = file.readLine() {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				// Discard comments.
				line = line[0:i]
			}
			f := getFields(line)
			if len(f) < 2 {
				continue
			}
			addr := parseLiteralIP(f[0])
			if addr == "" {
				continue
			}

			var canonical string
			for i := 1; i < len(f); i++ {
				name := absDomainName(f[i])
				h := []byte(f[i])
				lowerASCIIBytes(h)
				key := absDomainName(string(h))

				if i == 1 {
					canonical = key
				}

				is[addr] = append(is[addr], name)

				if v, ok := hs[key]; ok {
					hs[key] = byName{
						addrs:         append(v.addrs, addr),
						canonicalName: v.canonicalName,
					}
					continue
				}

				hs[key] = byName{
					addrs:         []string{addr},
					canonicalName: canonical,
				}
			}
		}
	}
	// Update the data cache.
	hosts.expire = now.Add(cacheMaxAge)
	hosts.path = hp
	hosts.byName = hs
	hosts.byAddr = is
	hosts.mtime = mtime
	hosts.size = size
}

// LookupStaticHost looks up the addresses and the canonical name for the given host from /etc/hosts.
func LookupStaticHost(host string) ([]string, string) {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	if len(hosts.byName) != 0 {
		if hasUpperCase(host) {
			lowerHost := []byte(host)
			lowerASCIIBytes(lowerHost)
			host = string(lowerHost)
		}
		if byName, ok := hosts.byName[absDomainName(host)]; ok {
			ipsCp := make([]string, len(byName.addrs))
			copy(ipsCp, byName.addrs)
			return ipsCp, byName.canonicalName
		}
	}
	return nil, ""
}

// LookupStaticAddr looks up the hosts for the given address from /etc/hosts.
func LookupStaticAddr(addr string) []string {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	addr = parseLiteralIP(addr)
	if addr == "" {
		return nil
	}
	if len(hosts.byAddr) != 0 {
		if hosts, ok := hosts.byAddr[addr]; ok {
			hostsCp := make([]string, len(hosts))
			copy(hostsCp, hosts)
			return hostsCp
		}
	}
	return nil
}

func stat(name string) (mtime time.Time, size int64, err error) {
	st, err := os.Stat(name)
	if err != nil {
		return time.Time{}, 0, err
	}
	return st.ModTime(), st.Size(), nil
}

type file struct {
	file  *os.File
	data  []byte
	atEOF bool
}

func (f *file) close() { f.file.Close() }

func (f *file) getLineFromData() (s string, ok bool) {
	data := f.data
	i := 0
	for i = 0; i < len(data); i++ {
		if data[i] == '\n' {
			s = string(data[0:i])
			ok = true
			// move data
			i++
			n := len(data) - i
			copy(data[0:], data[i:])
			f.data = data[0:n]
			return
		}
	}
	if f.atEOF && len(f.data) > 0 {
		// EOF, return all we have
		s = string(data)
		f.data = f.data[0:0]
		ok = true
	}
	return
}

func (f *file) readLine() (s string, ok bool) {
	if s, ok = f.getLineFromData(); ok {
		return
	}
	if len(f.data) < cap(f.data) {
		ln := len(f.data)
		n, err := io.ReadFull(f.file, f.data[ln:cap(f.data)])
		if n >= 0 {
			f.data = f.data[0 : ln+n]
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			f.atEOF = true
		}
	}
	s, ok = f.getLineFromData()
	return
}

func (f *file) stat() (mtime time.Time, size int64, err error) {
	st, err := f.file.Stat()
	if err != nil {
		return time.Time{}, 0, err
	}
	return st.ModTime(), st.Size(), nil
}

func open(name string) (*file, error) {
	fd, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return &file{fd, make([]byte, 0, 64*1024), false}, nil
}

func getFields(s string) []string { return splitAtBytes(s, " \r\t\n") }

// Count occurrences in s of any bytes in t.
func countAnyByte(s string, t string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			n++
		}
	}
	return n
}

// Split s at any bytes in t.
func splitAtBytes(s string, t string) []string {
	a := make([]string, 1+countAnyByte(s, t))
	n := 0
	last := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			if last < i {
				a[n] = s[last:i]
				n++
			}
			last = i + 1
		}
	}
	if last < len(s) {
		a[n] = s[last:]
		n++
	}
	return a[0:n]
}

// lowerASCIIBytes makes x ASCII lowercase in-place.
func lowerASCIIBytes(x []byte) {
	for i, b := range x {
		if 'A' <= b && b <= 'Z' {
			x[i] += 'a' - 'A'
		}
	}
}

// hasUpperCase tells whether the given string contains at least one upper-case.
func hasUpperCase(s string) bool {
	for i := range s {
		if 'A' <= s[i] && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// absDomainName returns an absolute domain name which ends with a
// trailing dot to match pure Go reverse resolver and all other lookup
// routines.
// See golang.org/issue/12189.
// But we don't want to add dots for local names from /etc/hosts.
// It's hard to tell so we settle on the heuristic that names without dots
// (like "localhost" or "myhost") do not get trailing dots, but any other
// names do.
func absDomainName(s string) string {
	if strings.IndexByte(s, '.') != -1 && s[len(s)-1] != '.' {
		s += "."
	}
	return s
}
