package singleflight

import (
	"testing"
	"time"
)

func TestDoChanWithOwner(t *testing.T) {
	var group Group[int]
	started, release := make(chan struct{}), make(chan struct{})
	owner, created := group.DoChanWithOwner("key", func() (int, error) { close(started); <-release; return 7, nil })
	if !created {
		t.Fatal("first caller did not own work")
	}
	<-started
	follower, created := group.DoChanWithOwner("key", func() (int, error) { t.Error("follower executed"); return 0, nil })
	if created {
		t.Fatal("follower claimed work")
	}
	close(release)
	for _, ch := range []<-chan Result[int]{owner, follower} {
		select {
		case got := <-ch:
			if got.Val != 7 || got.Err != nil || !got.Shared {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("missing result")
		}
	}
	next, created := group.DoChanWithOwner("key", func() (int, error) { return 9, nil })
	if !created || (<-next).Val != 9 {
		t.Fatal("completed work was retained")
	}
}
