package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

const (
	singleMTU        = 1420
	multihopInnerMTU = 1340
	multihopOuterMTU = 1420
	keepaliveSeconds = 25
	handshakeTimeout = 15 * time.Second
)

// hopConfig is one enrolled gateway and the transport chosen for it.
type hopConfig struct {
	IP         string
	Port       int
	PublicKey  string
	AssignedIP string
	Obfs       string
	DNS        string
}

// tunnelOptions describes a single- or multi-hop userspace tunnel. When Exit is
// nil the tunnel is single-hop; otherwise Entry is the outer hop and Exit the
// inner one.
type tunnelOptions struct {
	PrivateKey string
	Entry      hopConfig
	Exit       *hopConfig
	Transport  Transport
	DNSChoice  string
	Verbose    bool
}

// Tunnel owns one or two WireGuard devices plus the gVisor netstack that proxy
// connections are dialed on. No TUN device, root or OS route is touched.
type Tunnel struct {
	net    *netstack.Net
	inner  *device.Device
	outer  *device.Device
	bridge *tlsBridge

	Transport  string
	AssignedIP string
	Endpoint   string
	StartedAt  time.Time
}

func parseAssignedIP(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("gateway assigned an invalid address %q: %w", value, err)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr, nil
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// obfsUAPI renders AmneziaWG device-level parameters. They must be written
// before the first public_key= line, and every field has to match the gateway.
func obfsUAPI(t Transport) (string, error) {
	if t.Type != "awg" {
		return "", nil
	}
	required := []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}
	vals := make([]int, len(required))
	for i, key := range required {
		raw, ok := t.Params[key]
		if !ok {
			return "", fmt.Errorf("awg transport is missing parameter %q", key)
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return "", fmt.Errorf("awg parameter %q is invalid: %q", key, raw)
		}
		vals[i] = n
	}
	return fmt.Sprintf("jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7], vals[8]), nil
}

// drainPendingUp consumes the EventUp that netstack.CreateNetTUN queues before
// device.NewDevice starts its event reader. Swallowing it avoids the bring-up
// racing the obfuscation IpcSet inside amneziawg-go.
func drainPendingUp(t tun.Device) {
	for {
		select {
		case <-t.Events():
		default:
			return
		}
	}
}

func logLevel(verbose bool) int {
	if verbose {
		return device.LogLevelVerbose
	}
	return device.LogLevelError
}

// startTunnel brings the data plane up and waits for a real handshake. A device
// that reports "up" is not enough: only a reply from the gateway proves the
// transport works.
func startTunnel(ctx context.Context, opts tunnelOptions) (*Tunnel, error) {
	privHex, err := b64ToHex(opts.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}

	if opts.Exit != nil {
		return startMultihop(ctx, opts, privHex)
	}
	return startSingle(ctx, opts, privHex)
}

func startSingle(ctx context.Context, opts tunnelOptions, privHex string) (*Tunnel, error) {
	gw := opts.Entry
	serverHex, err := b64ToHex(gw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("server key: %w", err)
	}
	assigned, err := parseAssignedIP(gw.AssignedIP)
	if err != nil {
		return nil, err
	}
	obfs, err := obfsUAPI(opts.Transport)
	if err != nil {
		return nil, err
	}

	endpointHost := gw.IP
	endpointPort := gw.Port
	var bridge *tlsBridge
	if opts.Transport.Type == "wg-tls" {
		sni := opts.Transport.Params["sni"]
		if sni == "" {
			sni = gw.IP
		}
		bridge, err = dialTLSBridge(ctx, net.JoinHostPort(gw.IP, strconv.Itoa(gw.Port)), sni)
		if err != nil {
			return nil, fmt.Errorf("wg-tls bridge: %w", err)
		}
		host, portStr, splitErr := net.SplitHostPort(bridge.localEndpoint())
		if splitErr != nil {
			_ = bridge.Close()
			return nil, splitErr
		}
		port, _ := strconv.Atoi(portStr)
		endpointHost, endpointPort = host, port
	}

	tunDev, proxyNet, err := netstack.CreateNetTUN(
		[]netip.Addr{assigned},
		dnsServersFor(opts.DNSChoice, gw.DNS),
		singleMTU,
	)
	if err != nil {
		if bridge != nil {
			_ = bridge.Close()
		}
		return nil, fmt.Errorf("netstack: %w", err)
	}
	drainPendingUp(tunDev)
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(logLevel(opts.Verbose), "wg "))

	cfg := fmt.Sprintf("private_key=%s\n", privHex) + obfs + fmt.Sprintf(
		"public_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n",
		serverHex, net.JoinHostPort(endpointHost, strconv.Itoa(endpointPort)), keepaliveSeconds,
	)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		if bridge != nil {
			_ = bridge.Close()
		}
		return nil, fmt.Errorf("configure tunnel: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		if bridge != nil {
			_ = bridge.Close()
		}
		return nil, fmt.Errorf("bring tunnel up: %w", err)
	}

	t := &Tunnel{
		net: proxyNet, inner: dev, bridge: bridge,
		Transport: opts.Transport.Type, AssignedIP: assigned.String(),
		Endpoint: net.JoinHostPort(gw.IP, strconv.Itoa(gw.Port)), StartedAt: time.Now(),
	}
	if err := t.waitHandshake(ctx, handshakeTimeout); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// waitHandshake treats rx_bytes or a handshake timestamp as proof of life.
// tx_bytes is deliberately ignored: WireGuard retries initiations forever, so
// tx climbs on a dead tunnel.
func (t *Tunnel) waitHandshake(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		rx, _, hs := t.Stats()
		if rx > 0 || hs > 0 {
			return nil
		}
		if err := t.bridgeError(); err != nil {
			return fmt.Errorf("%s transport failed: %w", t.Transport, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s transport: no handshake from the gateway after %s", t.Transport, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (t *Tunnel) bridgeError() error {
	if t.bridge == nil {
		return nil
	}
	return t.bridge.Err()
}

// Stats reads cumulative counters and the last handshake time from the inner
// device (the one carrying user traffic).
func (t *Tunnel) Stats() (rxBytes, txBytes, lastHandshakeSec int64) {
	if t.inner == nil {
		return 0, 0, 0
	}
	get, err := t.inner.IpcGet()
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(get, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "rx_bytes":
			rxBytes = n
		case "tx_bytes":
			txBytes = n
		case "last_handshake_time_sec":
			lastHandshakeSec = n
		}
	}
	return
}

// Healthy reports whether the session still looks alive. WireGuard rekeys
// every ~120s, so a handshake older than staleAfter means dead.
func (t *Tunnel) Healthy(staleAfter time.Duration) bool {
	if t.TunnelUp() == false {
		return false
	}
	if err := t.bridgeError(); err != nil {
		return false
	}
	_, _, hs := t.Stats()
	if hs == 0 {
		return false
	}
	return time.Since(time.Unix(hs, 0)) < staleAfter
}

func (t *Tunnel) TunnelUp() bool {
	if t.inner == nil {
		return false
	}
	_, err := t.inner.IpcGet()
	return err == nil
}

func (t *Tunnel) Close() {
	if t.inner != nil {
		t.inner.Close()
		t.inner = nil
	}
	if t.outer != nil {
		t.outer.Close()
		t.outer = nil
	}
	if t.bridge != nil {
		_ = t.bridge.Close()
		t.bridge = nil
	}
	t.net = nil
}

// startMultihop stacks two devices: the outer one tunnels to the entry, and the
// inner one's socket is a UDP connection on the outer netstack, so exit-bound
// handshakes and traffic ride the entry tunnel. The entry forwards UDP:51820 to
// the exit (fleet allow-list). We never do this over the wg-tls bridge: nesting
// the length-prefixed TLS framing inside another tunnel is not implemented, so
// a stealth-only entry is rejected instead of silently degraded.
func startMultihop(ctx context.Context, opts tunnelOptions, privHex string) (*Tunnel, error) {
	if opts.Transport.Type == "wg-tls" {
		return nil, fmt.Errorf("multi-hop needs a UDP entry hop; %s cannot be the entry transport", opts.Transport.Type)
	}
	entry, exit := opts.Entry, *opts.Exit
	entryHex, err := b64ToHex(entry.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("entry key: %w", err)
	}
	exitHex, err := b64ToHex(exit.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("exit key: %w", err)
	}
	entryAssigned, err := parseAssignedIP(entry.AssignedIP)
	if err != nil {
		return nil, err
	}
	exitAssigned, err := parseAssignedIP(exit.AssignedIP)
	if err != nil {
		return nil, err
	}
	exitAddr, err := netip.ParseAddr(exit.IP)
	if err != nil {
		return nil, fmt.Errorf("exit gateway address %q: %w", exit.IP, err)
	}
	obfs, err := obfsUAPI(opts.Transport)
	if err != nil {
		return nil, err
	}

	outerTun, outerNet, err := netstack.CreateNetTUN(
		[]netip.Addr{entryAssigned},
		[]netip.Addr{entryAssigned}, // the outer device never resolves names
		multihopOuterMTU,
	)
	if err != nil {
		return nil, fmt.Errorf("outer netstack: %w", err)
	}
	drainPendingUp(outerTun)
	outer := device.NewDevice(outerTun, conn.NewDefaultBind(), device.NewLogger(logLevel(opts.Verbose), "outer "))
	outerCfg := fmt.Sprintf("private_key=%s\n", privHex) + obfs + fmt.Sprintf(
		"public_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=%d\n",
		entryHex, net.JoinHostPort(entry.IP, strconv.Itoa(entry.Port)), exitAddr, keepaliveSeconds,
	)
	if err := outer.IpcSet(outerCfg); err != nil {
		outer.Close()
		return nil, fmt.Errorf("configure entry hop: %w", err)
	}
	if err := outer.Up(); err != nil {
		outer.Close()
		return nil, fmt.Errorf("bring entry hop up: %w", err)
	}

	innerTun, innerNet, err := netstack.CreateNetTUN(
		[]netip.Addr{exitAssigned},
		dnsServersFor(opts.DNSChoice, exit.DNS),
		multihopInnerMTU,
	)
	if err != nil {
		outer.Close()
		return nil, fmt.Errorf("inner netstack: %w", err)
	}
	drainPendingUp(innerTun)
	exitEndpoint := netip.AddrPortFrom(exitAddr, uint16(exit.Port))
	inner := device.NewDevice(innerTun, newNetstackBind(outerNet, exitEndpoint), device.NewLogger(logLevel(opts.Verbose), "inner "))
	innerCfg := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n",
		privHex, exitHex, exitEndpoint, keepaliveSeconds,
	)
	if err := inner.IpcSet(innerCfg); err != nil {
		inner.Close()
		outer.Close()
		return nil, fmt.Errorf("configure exit hop: %w", err)
	}
	if err := inner.Up(); err != nil {
		inner.Close()
		outer.Close()
		return nil, fmt.Errorf("bring exit hop up: %w", err)
	}

	t := &Tunnel{
		net: innerNet, inner: inner, outer: outer,
		Transport: opts.Transport.Type, AssignedIP: exitAssigned.String(),
		Endpoint: net.JoinHostPort(exit.IP, strconv.Itoa(exit.Port)), StartedAt: time.Now(),
	}
	// Two handshakes run in series (entry first, then exit through it).
	if err := t.waitHandshake(ctx, 2*handshakeTimeout); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}
