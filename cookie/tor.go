package cookie

import (
	"context"
	"fmt"

	"github.com/cretz/bine/tor"
)

// StartTor launches a private, bridge-managed Tor process (via a local
// "tor" executable found on PATH) and returns it along with a
// DialContextFunc that routes connections through it. Nothing external
// needs to be running — the bridge owns the process's entire lifecycle.
// The caller must Close() the returned instance on shutdown.
func StartTor(ctx context.Context) (*tor.Tor, DialContextFunc, error) {
	t, err := tor.Start(ctx, &tor.StartConf{EnableNetwork: true})
	if err != nil {
		return nil, nil, fmt.Errorf("starting Tor process: %w", err)
	}
	dialer, err := t.Dialer(ctx, nil)
	if err != nil {
		t.Close()
		return nil, nil, fmt.Errorf("creating Tor dialer: %w", err)
	}
	return t, dialer.DialContext, nil
}
