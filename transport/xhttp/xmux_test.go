package xhttp

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestClientSlotShouldDrop(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		slot *clientSlot
		now  time.Time
		want bool
	}{
		{
			name: "not expired",
			slot: &clientSlot{
				expiry:           now.Add(time.Hour),
				remainingUses:    10,
				remainingRequest: 10,
				cfg:              normalizedXmux{reuseRange: Range{From: 5, To: 10}, requestRange: Range{From: 5, To: 10}},
			},
			now:  now,
			want: false,
		},
		{
			name: "expired by time",
			slot: &clientSlot{
				expiry:           now.Add(-time.Hour),
				remainingUses:    10,
				remainingRequest: 10,
			},
			now:  now,
			want: true,
		},
		{
			name: "zero remaining uses",
			slot: &clientSlot{
				remainingUses:    0,
				remainingRequest: 10,
				cfg:              normalizedXmux{reuseRange: Range{From: 5, To: 10}},
			},
			now:  now,
			want: true,
		},
		{
			name: "zero remaining requests",
			slot: &clientSlot{
				remainingUses:    10,
				remainingRequest: 0,
				cfg:              normalizedXmux{requestRange: Range{From: 5, To: 10}},
			},
			now:  now,
			want: true,
		},
		{
			name: "zero expiry never expires",
			slot: &clientSlot{
				expiry:           time.Time{},
				remainingUses:    10,
				remainingRequest: 10,
			},
			now:  now.Add(time.Hour * 1000),
			want: false,
		},
		{
			name: "zero uses with no range",
			slot: &clientSlot{
				remainingUses:    0,
				remainingRequest: 10,
				cfg:              normalizedXmux{},
			},
			now:  now,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.shouldDrop(tt.now)
			if got != tt.want {
				t.Errorf("shouldDrop() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientSlotRelease(t *testing.T) {
	slot := &clientSlot{}
	slot.openUsage.Store(5)

	slot.release()

	if got := slot.openUsage.Load(); got != 4 {
		t.Errorf("release() openUsage = %d, want 4", got)
	}
}

func TestClientSlotClose(t *testing.T) {
	slot := &clientSlot{
		client: &http.Client{},
	}

	slot.close()
	slot.close()
}

func TestXmuxManagerAcquireCreatesNew(t *testing.T) {
	callCount := 0
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 10, maxConnections: 5},
		newClient: func() (*clientSlot, error) {
			callCount++
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    10,
				remainingRequest: 10,
			}, nil
		},
	}

	slot, err := manager.acquire()
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	if slot == nil {
		t.Fatal("acquire() returned nil slot")
	}
	if callCount != 1 {
		t.Errorf("newClient called %d times, want 1", callCount)
	}
	if len(manager.clients) != 1 {
		t.Errorf("manager has %d clients, want 1", len(manager.clients))
	}
}

func TestXmuxManagerAcquireReusesExisting(t *testing.T) {
	callCount := 0
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 10, maxConnections: 5},
		newClient: func() (*clientSlot, error) {
			callCount++
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    10,
				remainingRequest: 10,
			}, nil
		},
	}

	slot1, _ := manager.acquire()
	slot1.release()

	slot2, err := manager.acquire()
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}

	if slot1 != slot2 {
		t.Error("acquire() should reuse existing slot")
	}
	if callCount != 1 {
		t.Errorf("newClient called %d times, want 1", callCount)
	}
}

func TestXmuxManagerAcquireRespectsMaxConcurrency(t *testing.T) {
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 1, maxConnections: 5},
		newClient: func() (*clientSlot, error) {
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    100,
				remainingRequest: 100,
			}, nil
		},
	}

	slot1, _ := manager.acquire()
	slot2, _ := manager.acquire()

	if slot1 == slot2 {
		t.Error("With maxConcurrency=1, should create new slot when first is in use")
	}

	if len(manager.clients) != 2 {
		t.Errorf("manager has %d clients, want 2", len(manager.clients))
	}
}

func TestXmuxManagerAcquireRespectsMaxConnections(t *testing.T) {
	callCount := 0
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 1, maxConnections: 2},
		newClient: func() (*clientSlot, error) {
			callCount++
			slot := &clientSlot{
				client:           &http.Client{},
				remainingUses:    100,
				remainingRequest: 100,
			}
			slot.openUsage.Store(1)
			return slot, nil
		},
	}

	slot1, _ := manager.acquire()
	slot2, _ := manager.acquire()
	slot3, _ := manager.acquire()

	if callCount > 2 {
		t.Errorf("newClient called %d times, want <= 2 (maxConnections)", callCount)
	}

	if slot3 != slot1 && slot3 != slot2 {
		t.Error("With maxConnections=2, third acquire should reuse slot1 or slot2")
	}
}

func TestXmuxManagerCleansExpired(t *testing.T) {
	now := time.Now()
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 10, maxConnections: 10},
		newClient: func() (*clientSlot, error) {
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    10,
				remainingRequest: 10,
				expiry:           now.Add(-time.Hour),
			}, nil
		},
	}

	slot1, _ := manager.acquire()
	slot1.release()

	manager.acquire()

	if len(manager.clients) != 1 {
		t.Errorf("manager has %d clients after cleanup, want 1", len(manager.clients))
	}
}

func TestXmuxManagerDecrementsCounters(t *testing.T) {
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 10, maxConnections: 10},
		newClient: func() (*clientSlot, error) {
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    5,
				remainingRequest: 10,
			}, nil
		},
	}

	slot, _ := manager.acquire()

	if slot.openUsage.Load() != 1 {
		t.Errorf("openUsage = %d, want 1", slot.openUsage.Load())
	}
	if slot.remainingUses != 4 {
		t.Errorf("remainingUses = %d, want 4", slot.remainingUses)
	}
	if slot.remainingRequest != 9 {
		t.Errorf("remainingRequest = %d, want 9", slot.remainingRequest)
	}
}

func TestXmuxManagerConcurrentAccess(t *testing.T) {
	manager := &xmuxManager{
		cfg: normalizedXmux{maxConcurrency: 5, maxConnections: 10},
		newClient: func() (*clientSlot, error) {
			return &clientSlot{
				client:           &http.Client{},
				remainingUses:    1000,
				remainingRequest: 1000,
			}, nil
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot, err := manager.acquire()
			if err != nil {
				t.Errorf("acquire() error = %v", err)
				return
			}
			if slot == nil {
				t.Error("acquire() returned nil")
				return
			}
			time.Sleep(time.Millisecond)
			slot.release()
		}()
	}
	wg.Wait()
}

func TestAcquireClientCreatesManager(t *testing.T) {
	key := "test-key-" + time.Now().String()
	cfg := normalizedXmux{maxConcurrency: 5, maxConnections: 10}

	slot, err := acquireClient(key, cfg, func() (*clientSlot, error) {
		return &clientSlot{
			client:           &http.Client{},
			remainingUses:    10,
			remainingRequest: 10,
		}, nil
	})

	if err != nil {
		t.Fatalf("acquireClient() error = %v", err)
	}
	if slot == nil {
		t.Fatal("acquireClient() returned nil")
	}

	xmuxRegistry.Delete(key)
}

func TestAcquireClientReusesManager(t *testing.T) {
	key := "test-reuse-" + time.Now().String()
	cfg := normalizedXmux{maxConcurrency: 5, maxConnections: 10}

	callCount := 0
	factory := func() (*clientSlot, error) {
		callCount++
		return &clientSlot{
			client:           &http.Client{},
			remainingUses:    10,
			remainingRequest: 10,
		}, nil
	}

	slot1, _ := acquireClient(key, cfg, factory)
	slot1.release()

	slot2, _ := acquireClient(key, cfg, factory)

	if slot1 != slot2 {
		t.Error("acquireClient() should reuse same manager and slot")
	}
	if callCount != 1 {
		t.Errorf("factory called %d times, want 1", callCount)
	}

	xmuxRegistry.Delete(key)
}

func TestNormalizedXmuxNewSlotLimits(t *testing.T) {
	cfg := normalizedXmux{
		reuseRange:    Range{From: 5, To: 10},
		requestRange:  Range{From: 100, To: 200},
		reusableRange: Range{From: 60, To: 120},
	}

	uses, requests, expiry := cfg.newSlotLimits()

	if uses < 5 || uses > 10 {
		t.Errorf("uses = %d, want in [5, 10]", uses)
	}
	if requests < 100 || requests > 200 {
		t.Errorf("requests = %d, want in [100, 200]", requests)
	}
	if expiry.IsZero() {
		t.Error("expiry should not be zero")
	}
	if time.Until(expiry) < 59*time.Second || time.Until(expiry) > 121*time.Second {
		t.Errorf("expiry = %v, want in ~60-120 seconds from now", expiry)
	}
}

func TestNormalizedXmuxNewSlotLimitsZeroRanges(t *testing.T) {
	cfg := normalizedXmux{}

	uses, requests, expiry := cfg.newSlotLimits()

	if uses != 0 {
		t.Errorf("uses = %d, want 0", uses)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0 (zero range means no limit)", requests)
	}
	if !expiry.IsZero() {
		t.Errorf("expiry = %v, want zero", expiry)
	}
}
