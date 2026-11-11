package iface

import (
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Requesting unused DNS-server and multicast lists can make Windows adapter
// enumeration several times slower. Compare against the required native data.
func TestWindowsSnapshotAvoidsUnusedEnumerationCost(t *testing.T) {
	if os.Getenv("MIHOMO_IFACE_LIVE_TEST") != "1" {
		t.Skip("set MIHOMO_IFACE_LIVE_TEST=1 on a stationary Windows network")
	}
	minimalEnumeration := func() error {
		size := uint32(15000)
		for {
			buffer := make([]byte, size)
			// Keep unicast, anycast, prefix and gateway semantics intact.
			const flags = windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS |
				windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_SKIP_MULTICAST
			err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
				(*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
			if err == nil {
				return nil
			}
			if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buffer)) {
				return err
			}
		}
	}
	operations := [2]func() error{
		minimalEnumeration,
		func() error {
			_, err := readInterfaceSnapshot()
			return err
		},
	}
	var samples [2][]time.Duration
	for round := 0; round < 7; round++ {
		// Alternate the first operation to reduce cache and scheduling bias.
		for offset := 0; offset < 2; offset++ {
			index := (round + offset) % 2
			start := time.Now()
			if err := operations[index](); err != nil {
				t.Fatal(err)
			}
			samples[index] = append(samples[index], time.Since(start))
		}
	}
	for _, durations := range samples {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	}
	baseline, actual := samples[0][3], samples[1][3]
	t.Logf("minimal_enumeration_median=%s snapshot_median=%s ratio=%.2f", baseline, actual, float64(actual)/float64(baseline))
	// Permit decoding and scheduling overhead without a fixed latency SLA.
	if actual > baseline*2+5*time.Millisecond {
		t.Fatalf("snapshot enumeration exceeds the cost of required adapter data: %s versus %s", actual, baseline)
	}
}

// This opt-in regression test measures the real Windows API on a stationary
// network. It catches N+1 full adapter enumerations during one cache refresh.
func TestWindowsRefreshLatency(t *testing.T) {
	if os.Getenv("MIHOMO_IFACE_LIVE_TEST") != "1" {
		t.Skip("set MIHOMO_IFACE_LIVE_TEST=1 on a stationary Windows network")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) < 8 {
		t.Skip("at least eight interfaces are needed to expose the regression")
	}
	var enumeration, refresh []time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		if _, err := net.Interfaces(); err != nil {
			t.Fatal(err)
		}
		enumeration = append(enumeration, time.Since(start))
		FlushCache()
		start = time.Now()
		if _, err := getCache(); err != nil {
			t.Fatal(err)
		}
		refresh = append(refresh, time.Since(start))
	}
	sort.Slice(enumeration, func(i, j int) bool { return enumeration[i] < enumeration[j] })
	sort.Slice(refresh, func(i, j int) bool { return refresh[i] < refresh[j] })
	baseline, actual := enumeration[2], refresh[2]
	t.Logf("interfaces=%d enumerate_median=%s refresh_median=%s ratio=%.2f", len(interfaces), baseline, actual, float64(actual)/float64(baseline))
	// Allow substantial scheduling noise; an N+1 enumeration still exceeds this
	// on hosts with many virtual adapters. No fixed millisecond SLA is assumed.
	if actual > baseline*5+10*time.Millisecond {
		t.Fatalf("cache refresh repeats expensive whole-adapter enumeration: %s versus %s", actual, baseline)
	}
}

// Compare public interface metadata and address prefixes against the standard
// library, including disconnected adapters needed by explicit interface binding.
func TestWindowsSnapshotPreservesInterfaceData(t *testing.T) {
	if os.Getenv("MIHOMO_IFACE_LIVE_TEST") != "1" {
		t.Skip("set MIHOMO_IFACE_LIVE_TEST=1 on a stationary Windows network")
	}
	standard, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	FlushCache()
	actual, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(standard) {
		t.Fatalf("interface count: got %d, want %d", len(actual), len(standard))
	}
	for _, want := range standard {
		got, exists := actual[want.Name]
		if !exists {
			t.Errorf("missing interface %q", want.Name)
			continue
		}
		if got.Index != want.Index || got.MTU != want.MTU || got.Flags != want.Flags || !reflect.DeepEqual(got.HardwareAddr, want.HardwareAddr) {
			t.Errorf("metadata mismatch for %q: got %+v, want %+v", want.Name, got, want)
		}
		addresses, err := want.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		var expected []string
		for _, addr := range addresses {
			if ipNet, ok := addr.(*net.IPNet); ok {
				prefix, err := netip.ParsePrefix(ipNet.String())
				if err != nil {
					t.Fatal(err)
				}
				expected = append(expected, prefix.String())
			} else if ipAddr, ok := addr.(*net.IPAddr); ok {
				ip, ok := netip.AddrFromSlice(ipAddr.IP)
				if !ok {
					t.Fatal("invalid standard-library IP")
				}
				ip = ip.Unmap()
				expected = append(expected, netip.PrefixFrom(ip, ip.BitLen()).String())
			}
		}
		var observed []string
		for _, prefix := range got.Addresses {
			observed = append(observed, prefix.String())
		}
		sort.Strings(expected)
		sort.Strings(observed)
		if !reflect.DeepEqual(expected, observed) {
			t.Errorf("address mismatch for %q: got %v, want %v", want.Name, observed, expected)
		}
	}
}
