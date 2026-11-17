package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// manager owns the live tunnel and reconnects it while the proxy listener stays
// up. currentTunnel() is what the proxy routes through; nil means "down", and
// tunnel-bound connections then fail closed instead of falling back to a direct
// connection.
type manager struct {
	mu     sync.RWMutex
	tunnel *Tunnel

	cfg     Config
	verbose bool
	proxy   *proxyServer
	fatal   chan struct{}

	entry RouteEndpoint
	exit  RouteEndpoint
	tr    string
}

func (m *manager) currentTunnel() *Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnel
}

func (m *manager) setTunnel(t *Tunnel) {
	m.mu.Lock()
	m.tunnel = t
	m.mu.Unlock()
}

type runOptions struct {
	listen      string
	httpListen  string
	country     string
	entry       string
	exit        string
	multihop    bool
	mode        string
	verbose     bool
	noKill      bool
	autoConnect bool
}

func parseRunOptions(args []string, cfg Config) (runOptions, error) {
	o := runOptions{
		listen: cfg.Listen, httpListen: cfg.HTTPListen,
		country: cfg.Country, mode: cfg.TransportMode,
		multihop: cfg.RouteStyle == "multihop", autoConnect: true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", arg)
			}
			i++
			return args[i], nil
		}
		var err error
		switch arg {
		case "--listen", "-l":
			o.listen, err = next()
		case "--http-listen", "--http":
			o.httpListen, err = next()
		case "--country", "-c":
			o.country, err = next()
		case "--entry":
			o.entry, err = next()
			o.multihop = true
		case "--exit":
			o.exit, err = next()
			o.multihop = true
		case "--multihop", "--multi":
			o.multihop = true
		case "--stealth":
			o.mode = "stealth"
		case "--speed":
			o.mode = "speed"
		case "--auto":
			o.mode = "auto"
		case "--verbose", "-v":
			o.verbose = true
		case "--no-kill-switch":
			o.noKill = true
		case "--no-reconnect":
			o.autoConnect = false
		default:
			err = fmt.Errorf("unknown run flag %q", arg)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

func runCommand(args []string) int {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			printUsage()
			return 0
		}
	}
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	opts, err := parseRunOptions(args, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\nrun --help for usage\n", err)
		return 2
	}
	if err := validateListen(opts.listen); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: socks5 %v\n", err)
		return 2
	}
	if err := validateListen(opts.httpListen); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: http %v\n", err)
		return 2
	}
	if opts.listen == opts.httpListen {
		fmt.Fprintln(os.Stderr, "fluxcore: SOCKS5 and HTTP listeners must use different addresses")
		return 2
	}
	if err := ensureIdentity(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: identity: %v\n", err)
		return 1
	}

	cfg.Listen = opts.listen
	cfg.HTTPListen = opts.httpListen
	cfg.Country = opts.country
	cfg.TransportMode = opts.mode
	cfg.KillSwitch = !opts.noKill
	cfg.AutoReconnect = opts.autoConnect
	if opts.multihop {
		cfg.RouteStyle = "multihop"
		cfg.Entry = opts.entry
		cfg.Exit = opts.exit
	} else {
		cfg.RouteStyle = "single"
		cfg.Entry, cfg.Exit = "", ""
	}

	split := compileSplit(cfg.Split, nil)
	m := &manager{cfg: cfg, verbose: opts.verbose, fatal: make(chan struct{})}
	proxy, err := newProxyServer(cfg.Listen, cfg.HTTPListen, m, split, cfg.KillSwitch, opts.verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	m.proxy = proxy

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Fluxcore CLI %s\n", version)
	fmt.Printf("socks5     on %s (loopback only)\n", proxy.SocksAddr())
	fmt.Printf("http       on %s (loopback only)\n", proxy.HTTPAddr())
	fmt.Printf("identity   %s\n", cfg.Keypair.PublicKey)
	fmt.Printf("region     %s\n", displaySelector(opts.country))
	modeLine := fmt.Sprintf("route      %s", cfg.RouteStyle)
	if opts.multihop {
		modeLine += fmt.Sprintf(" (%s → %s)", displaySelector(opts.entry), displaySelector(opts.exit))
	}
	fmt.Println(modeLine)
	fmt.Printf("transport  %s\n", opts.mode)
	fmt.Println("no TUN, no root, no system routes: only apps pointed at these proxies use it")
	fmt.Println()

	go m.loop(ctx)

	serveErr := make(chan error, 1)
	go func() { serveErr <- proxy.Serve() }()
	select {
	case <-ctx.Done():
		fmt.Println("\nshutting down…")
	case <-m.fatal:
		fmt.Println("tunnel lost and auto-reconnect is off")
	case err := <-serveErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxy: %v\n", err)
		}
	}
	_ = proxy.Close()
	m.shutdown()
	clearRuntimeState()
	return 0
}

func (m *manager) shutdown() {
	if t := m.currentTunnel(); t != nil {
		t.Close()
	}
	m.setTunnel(nil)
}

func (m *manager) loop(ctx context.Context) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		t, entry, exit, transport, err := m.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !m.cfg.AutoReconnect {
				fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
				close(m.fatal)
				return
			}
			fmt.Fprintf(os.Stderr, "connect failed: %v (retrying in %s)\n", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 2 * time.Second
		m.mu.Lock()
		m.entry, m.exit, m.tr = entry, exit, transport
		m.mu.Unlock()
		m.setTunnel(t)
		m.proxy.setSplit(compileSplit(m.cfg.Split, []string{entry.IP, exit.IP}))
		printConnected(entry, exit, transport, t)
		writeRuntimeState(m, t)

		healthy := m.monitor(ctx, t)
		t.Close()
		m.setTunnel(nil)
		if ctx.Err() != nil {
			return
		}
		if !healthy && !m.cfg.AutoReconnect {
			close(m.fatal)
			return
		}
		fmt.Println("tunnel lost; reconnecting…")
	}
}

// monitor returns false when the tunnel died. A WireGuard session that has not
// rekeyed in ~3 minutes is dead even if the device still claims to be up, which
// is the usual failure after a network change.
func (m *manager) monitor(ctx context.Context, t *Tunnel) bool {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return true
		case <-ticker.C:
			if t.Healthy(180 * time.Second) {
				writeRuntimeState(m, t)
				continue
			}
			return false
		}
	}
}

func printConnected(entry, exit RouteEndpoint, transport string, t *Tunnel) {
	fmt.Println("connected")
	if exit.IP == "" {
		fmt.Printf("  exit       %s %s (%s) via %s\n", entry.Flag, entry.Name, entry.City, transport)
	} else {
		fmt.Printf("  entry      %s %s (%s)\n", entry.Flag, entry.Name, entry.City)
		fmt.Printf("  exit       %s %s (%s) via %s\n", exit.Flag, exit.Name, exit.City, transport)
	}
	fmt.Printf("  endpoint   %s\n", t.Endpoint)
	fmt.Printf("  local IP   %s (inside the tunnel)\n", t.AssignedIP)
}

// ---- route selection -------------------------------------------------------

func displaySelector(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return "auto (fastest)"
	}
	return v
}

func rankGateways(list []GatewayInfo, latency map[string]int64) []GatewayInfo {
	out := append([]GatewayInfo(nil), list...)
	sort.SliceStable(out, func(i, j int) bool {
		li, lj := int64(1<<62), int64(1<<62)
		if v, ok := latency[out[i].IP]; ok {
			li = v
		}
		if v, ok := latency[out[j].IP]; ok {
			lj = v
		}
		if li != lj {
			return li < lj
		}
		return out[i].Load < out[j].Load
	})
	return out
}

func filterGateways(list []GatewayInfo, selector string) []GatewayInfo {
	code, city := normalizeCountrySelector(selector)
	if code == "" {
		return list
	}
	var out []GatewayInfo
	for _, gw := range list {
		if strings.ToUpper(gw.Country) != code {
			continue
		}
		if city != "" {
			loc := localityOf(gw.City, gw.Country)
			if !strings.Contains(strings.ToLower(loc), strings.ToLower(city)) {
				continue
			}
		}
		out = append(out, gw)
	}
	return out
}

// favoriteFirst puts saved locations ahead of the rest when no country was
// chosen explicitly, so `fluxcore favorites add` actually affects routing.
func favoriteFirst(list []GatewayInfo, favorites []string, latency map[string]int64) []GatewayInfo {
	if len(favorites) == 0 {
		return rankGateways(list, latency)
	}
	seen := map[string]bool{}
	out := make([]GatewayInfo, 0, len(list))
	for _, sel := range favorites {
		for _, gw := range rankGateways(filterGateways(list, sel), latency) {
			if !seen[gw.IP] {
				seen[gw.IP] = true
				out = append(out, gw)
			}
		}
	}
	for _, gw := range rankGateways(list, latency) {
		if !seen[gw.IP] {
			out = append(out, gw)
		}
	}
	return out
}

// planRoute turns the configured selectors into a list of hop candidates.
func planRoute(cfg Config, gateways []GatewayInfo, latency map[string]int64) (entries, exits []GatewayInfo, err error) {
	if cfg.RouteStyle != "multihop" && strings.TrimSpace(cfg.Country) == "" {
		entries = favoriteFirst(gateways, cfg.Favorites, latency)
	} else {
		entries = rankGateways(filterGateways(gateways, cfg.Country), latency)
	}
	if cfg.RouteStyle == "multihop" {
		entrySel := cfg.Entry
		if entrySel == "" {
			entrySel = cfg.Country
		}
		exitSel := cfg.Exit
		if exitSel == "" {
			exitSel = cfg.Country
		}
		entries = rankGateways(filterGateways(gateways, entrySel), latency)
		exits = rankGateways(filterGateways(gateways, exitSel), latency)
		if len(exits) == 0 {
			return nil, nil, fmt.Errorf("no gateways match the exit selector %q", displaySelector(exitSel))
		}
	} else {
		exits = entries
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no gateways match the entry selector %q", displaySelector(cfg.Country))
	}
	return entries, exits, nil
}

// ---- connect ---------------------------------------------------------------

func (m *manager) connect(ctx context.Context) (*Tunnel, RouteEndpoint, RouteEndpoint, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	gateways, latency, err := m.discover(cctx)
	if err != nil {
		return nil, RouteEndpoint{}, RouteEndpoint{}, "", err
	}
	entries, exits, err := planRoute(m.cfg, gateways, latency)
	if err != nil {
		return nil, RouteEndpoint{}, RouteEndpoint{}, "", err
	}

	if m.cfg.RouteStyle == "multihop" {
		attempts := 0
		var lastErr error
		for _, entryGW := range firstN(entries, 3) {
			for _, exitGW := range firstN(exits, 3) {
				if entryGW.IP == exitGW.IP {
					continue
				}
				if m.cfg.NodeDiversity && entryGW.Country == exitGW.Country {
					lastErr = fmt.Errorf("node diversity: entry and exit are both in %s", entryGW.Country)
					continue
				}
				attempts++
				if attempts > 6 {
					break
				}
				t, transport, err := m.connectMultihop(cctx, entryGW, exitGW)
				if err != nil {
					lastErr = err
					fmt.Fprintf(os.Stderr, "  multihop %s→%s: %v\n", entryGW.IP, exitGW.IP, err)
					continue
				}
				return t, routeEndpoint(entryGW), routeEndpoint(exitGW), transport, nil
			}
			if attempts > 6 {
				break
			}
		}
		if lastErr == nil {
			lastErr = errors.New("no usable entry/exit pair")
		}
		return nil, RouteEndpoint{}, RouteEndpoint{}, "", lastErr
	}

	var lastErr error
	for _, gw := range firstN(entries, 4) {
		t, transport, err := m.connectSingle(cctx, gw)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "  %s %s: %v\n", gw.Country, gw.IP, err)
			continue
		}
		return t, routeEndpoint(gw), RouteEndpoint{}, transport, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable gateway")
	}
	return nil, RouteEndpoint{}, RouteEndpoint{}, "", lastErr
}

func firstN(list []GatewayInfo, n int) []GatewayInfo {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

func (m *manager) discover(ctx context.Context) ([]GatewayInfo, map[string]int64, error) {
	specs, err := bundledSpecs()
	if err != nil {
		return nil, nil, err
	}
	nodes := bundledSeedNodes()
	if dir, err := loadBundledDirectory(); err == nil {
		nodes = append(nodes, directorySeedIPs(dir)...)
	}
	gateways, err := discoverFleet(ctx, specs, nodes)
	if err != nil {
		cache, cacheErr := loadFleetCache()
		if cacheErr != nil || len(cache.Gateways) == 0 {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "discovery failed (%v); using cached fleet\n", err)
		return cache.Gateways, cache.LatencyMs, nil
	}

	// Measure the fastest handful per selector instead of the whole fleet.
	measured := make([]GatewayInfo, 0, 12)
	if m.cfg.RouteStyle == "multihop" {
		for _, gw := range firstN(rankGateways(filterGateways(gateways, m.cfg.Entry), nil), 5) {
			measured = append(measured, gw)
		}
		for _, gw := range firstN(rankGateways(filterGateways(gateways, m.cfg.Exit), nil), 5) {
			measured = append(measured, gw)
		}
	} else {
		measured = firstN(rankGateways(filterGateways(gateways, m.cfg.Country), nil), 8)
	}
	latency := measureLatencySet(ctx, measured)
	saveFleetCache(gateways, latency)
	return gateways, latency, nil
}

func directorySeedIPs(dir Directory) []string {
	var out []string
	for _, seed := range dir.SeedGateways {
		if seed.IP == "" || seed.IP == "0.0.0.0" {
			continue
		}
		if net.ParseIP(seed.IP) != nil {
			out = append(out, seed.IP)
		}
	}
	return out
}

func measureLatencySet(ctx context.Context, gateways []GatewayInfo) map[string]int64 {
	out := make(map[string]int64)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, gw := range gateways {
		wg.Add(1)
		go func(gw GatewayInfo) {
			defer wg.Done()
			if ms := measureLatency(ctx, gw); ms != nil {
				mu.Lock()
				out[gw.IP] = *ms
				mu.Unlock()
			}
		}(gw)
	}
	wg.Wait()
	return out
}

func (m *manager) prepareHop(ctx context.Context, gw GatewayInfo) (EnrollResponse, []Transport, error) {
	pub := m.cfg.Keypair.PublicKey
	chain, err := requireTransport(gw.Transports, m.cfg.TransportMode)
	if err != nil {
		return EnrollResponse{}, nil, err
	}
	enroll, err := enrollAt(ctx, stripHostPort(gw.IP), pub, gw.SignPubkey)
	if err != nil {
		return EnrollResponse{}, nil, fmt.Errorf("enroll: %w", err)
	}
	return enroll, chain, nil
}

func (m *manager) connectSingle(ctx context.Context, gw GatewayInfo) (*Tunnel, string, error) {
	enroll, chain, err := m.prepareHop(ctx, gw)
	if err != nil {
		return nil, "", err
	}
	var lastErr error
	for _, tr := range chain {
		t, err := startTunnel(ctx, tunnelOptions{
			PrivateKey: m.cfg.Keypair.PrivateKey,
			Entry: hopConfig{
				IP: stripHostPort(gw.IP), Port: tr.Port, PublicKey: enroll.ServerPubkey,
				AssignedIP: enroll.AssignedIP, DNS: enroll.DNS,
			},
			Transport: tr, DNSChoice: m.cfg.DNS, Verbose: m.verbose,
		})
		if err != nil {
			lastErr = err
			continue
		}
		return t, tr.Type, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no transport available")
	}
	return nil, "", lastErr
}

func (m *manager) connectMultihop(ctx context.Context, entryGW, exitGW GatewayInfo) (*Tunnel, string, error) {
	entryEnroll, entryChain, err := m.prepareHop(ctx, entryGW)
	if err != nil {
		return nil, "", fmt.Errorf("entry: %w", err)
	}
	exitEnroll, _, err := m.prepareHop(ctx, exitGW)
	if err != nil {
		return nil, "", fmt.Errorf("exit: %w", err)
	}
	var lastErr error
	for _, tr := range entryChain {
		if tr.Type == "wg-tls" {
			lastErr = fmt.Errorf("the entry hop cannot use wg-tls in multi-hop mode")
			continue
		}
		t, err := startTunnel(ctx, tunnelOptions{
			PrivateKey: m.cfg.Keypair.PrivateKey,
			Entry: hopConfig{
				IP: stripHostPort(entryGW.IP), Port: tr.Port, PublicKey: entryEnroll.ServerPubkey,
				AssignedIP: entryEnroll.AssignedIP, DNS: entryEnroll.DNS,
			},
			Exit: &hopConfig{
				IP: stripHostPort(exitGW.IP), Port: wgPort, PublicKey: exitEnroll.ServerPubkey,
				AssignedIP: exitEnroll.AssignedIP, DNS: exitEnroll.DNS,
			},
			Transport: tr, DNSChoice: m.cfg.DNS, Verbose: m.verbose,
		})
		if err != nil {
			lastErr = err
			continue
		}
		return t, tr.Type, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no transport available")
	}
	return nil, "", lastErr
}

// ---- runtime state for `status` -------------------------------------------

type runtimeState struct {
	PID        int           `json:"pid"`
	Listen     string        `json:"listen"`
	HTTPListen string        `json:"httpListen"`
	RouteStyle string        `json:"routeStyle"`
	Entry      RouteEndpoint `json:"entry"`
	Exit       RouteEndpoint `json:"exit,omitempty"`
	Transport  string        `json:"transport"`
	AssignedIP string        `json:"assignedIp"`
	Since      int64         `json:"since"`
	RxBytes    int64         `json:"rxBytes"`
	TxBytes    int64         `json:"txBytes"`
	LastHs     int64         `json:"lastHandshake"`
}

func statePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime.json"), nil
}

func writeRuntimeState(m *manager, t *Tunnel) {
	path, err := statePath()
	if err != nil {
		return
	}
	m.mu.RLock()
	entry, exit, tr := m.entry, m.exit, m.tr
	m.mu.RUnlock()
	rx, tx, hs := t.Stats()
	st := runtimeState{
		PID: os.Getpid(), Listen: m.cfg.Listen, HTTPListen: m.cfg.HTTPListen,
		RouteStyle: m.cfg.RouteStyle,
		Entry:      entry, Exit: exit, Transport: tr, AssignedIP: t.AssignedIP,
		Since: t.StartedAt.Unix(), RxBytes: rx, TxBytes: tx, LastHs: hs,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		raw, err := json.MarshalIndent(st, "", "  ")
		if err == nil {
			_ = os.WriteFile(path, append(raw, '\n'), 0o600)
		}
	}
}

func clearRuntimeState() {
	if path, err := statePath(); err == nil {
		_ = os.Remove(path)
	}
}

func loadRuntimeState() (runtimeState, error) {
	var st runtimeState
	path, err := statePath()
	if err != nil {
		return st, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
