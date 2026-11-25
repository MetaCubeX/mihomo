# Isolated Darwin UDP reply-loop regression

This opt-in experiment injects one synthetic UDP reply into a temporary utun and observes the existing `handleUDPToLocal` receive/writeback path. It forces the first outbound socket to reuse a released client source port. Without the allocation guard, the reply can enter that socket and repeat until the test stops at 64 receives. With the guard, the socket is closed and reallocated before forwarding starts.

The runner creates only a new interface with `198.19.255.1/30`. It does not change an existing interface, Clash configuration, or default route. It refuses to proceed if that test address already exists or if the default interface is a utun/loopback interface. Closing the control socket destroys the temporary utun; cleanup also deletes its test address. Each child has a timeout. Run this only on a Darwin host where you can authorize creating a temporary interface. Python 3 is required; the example commands use uv. Loopback detection must be enabled.

The default route must name a physical interface with an IPv4 address returned by `ipconfig getifaddr`. An IPv6-only default interface or a default route through utun is unsupported by this runner. In those environments, use a separate host that meets these prerequisites.

Build the patched test binary from the repository root:

```shell
go test -c -o /tmp/mihomo-udp-guard.test ./tunnel
```

Run the TUN-address client scenario with the Python interpreter managed by uv:

```shell
sudo "$(uv run python -c 'import sys; print(sys.executable)')" test/proof/run_udp_reply_loop.py /tmp/mihomo-udp-guard.test
```

Run the physical-address client scenario:

```shell
sudo "$(uv run python -c 'import sys; print(sys.executable)')" test/proof/run_udp_reply_loop.py /tmp/mihomo-udp-guard.test physical
```

Both runs must report zero repeated writebacks after the single injected packet and pass `TestUDPForwardingAfterPortGuard`. The positive control uses a local UDP echo server; it checks the delivered payload and reply source IP/port, not only the exit status.

To reproduce the pre-fix behavior, copy only `tunnel/udp_reply_loop_darwin_test.go` and this runner into a separate checkout of v1.19.32, then build and run the same commands. The test detects whether `Detector.ListenPacket` exists. On the old source it uses DIRECT's original pre-check, native allocation, registration sequence; the collision test should fail after 64 receives, while the normal UDP control should pass. Do not apply the portable detector tests to the old checkout: they call the new method.

This is a controlled mechanism regression, not a full client acceptance test. It uses the native dialer, detector, UDP tracker, and unchanged core receive/writeback handler. A small connection wrapper and IPv4 frame writer substitute for the outbound adapter wrapper and full gvisor reply writer to avoid a test-package import cycle. Port reuse is forced, rather than waiting for a natural collision. The physical-address variant also uses IPv4; IPv6 TUN delivery, real QUIC sessions, sleep/wake, and network switching are outside this experiment.

Without the runner environment, these tests skip during ordinary `go test` runs.
