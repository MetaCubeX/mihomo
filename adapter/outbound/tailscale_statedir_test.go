//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUnstartedTailscale returns an outbound without a tsnet server, enough to exercise the state dir bookkeeping.
func newUnstartedTailscale(name, stateDir string) *Tailscale {
	ctx, cancel := context.WithCancel(context.Background())
	return &Tailscale{
		Base:          NewBase(BaseOption{Name: name, Type: C.Tailscale}),
		option:        TailscaleOption{Name: name, StateDir: stateDir},
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),
		generation:    tailscaleGeneration.Add(1),
	}
}

func TestTailscaleTakeOverStateDir(t *testing.T) {
	dir := t.TempDir()
	stale := newUnstartedTailscale("stale", dir) // from a config that was replaced before it was ever used
	old := newUnstartedTailscale("old", dir)
	cur := newUnstartedTailscale("current", dir)
	other := newUnstartedTailscale("other", t.TempDir())

	require.NoError(t, old.takeOverStateDir())
	require.NoError(t, other.takeOverStateDir())

	require.NoError(t, cur.takeOverStateDir())
	assert.Error(t, old.ctx.Err(), "the outdated outbound on the same state dir is closed")
	assert.ErrorIs(t, old.start(), errTailscaleClosed)
	assert.NoError(t, other.ctx.Err(), "an outbound on another state dir is left alone")

	// start returns before touching the (nil) tsnet server
	assert.Error(t, stale.start(), "an older outbound cannot take the state dir back")
	assert.NoError(t, cur.ctx.Err())

	require.NoError(t, cur.Close())
	require.NoError(t, cur.Close())
	require.NoError(t, other.Close())
	tailscaleStateDirOwnersMu.Lock()
	defer tailscaleStateDirOwnersMu.Unlock()
	assert.Empty(t, tailscaleStateDirOwners)
}
