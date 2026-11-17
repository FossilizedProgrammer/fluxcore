package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- directory -------------------------------------------------------------

//go:embed data/directory.json
var bundledDirectoryJSON []byte

var (
	bundledDirectoryOnce sync.Once
	bundledDirectory     Directory
	bundledDirectoryErr  error
)

// loadBundledDirectory returns the verified bundled snapshot. The whole trust
// chain hangs off the pinned directory key, so an unverified snapshot is
// rejected outright.
func loadBundledDirectory() (Directory, error) {
	bundledDirectoryOnce.Do(func() {
		if err := json.Unmarshal(bundledDirectoryJSON, &bundledDirectory); err != nil {
			bundledDirectoryErr = fmt.Errorf("bundled directory: %w", err)
			return
		}
		if !directoryVerify(bundledDirectory, directoryPublicKey) {
			bundledDirectoryErr = errDirectoryInvalid
		}
	})
	return bundledDirectory, bundledDirectoryErr
}

func bundledSpecs() ([]string, error) {
	dir, err := loadBundledDirectory()
	if err != nil {
		return nil, err
	}
	return dir.Specs, nil
}

func bundledSeedNodes() []string {
	dir, err := loadBundledDirectory()
	if err != nil {
		return nil
	}
	var out []string
	for _, g := range dir.SeedGateways {
		if g.IP != "" && g.IP != "0.0.0.0" {
			out = append(out, g.IP)
		}
	}
	return out
}

// ---- discovery -------------------------------------------------------------

const (
	fluxAPI            = "https://api.runonflux.io"
	fluxNodePort       = 16127
	discoveryTimeout   = 5 * time.Second
	locationTimeout    = 10 * time.Second
	defaultRequestTime = 12 * time.Second
	enrollRequestTime  = 15 * time.Second
	pingSampleTimeout  = 10 * time.Second
	pingSamples        = 2
)

func specToCountryCode(spec string) string {
	s := strings.TrimPrefix(spec, "cumulusvpn")
	if strings.HasPrefix(s, "tls") {
		s = strings.TrimPrefix(s, "tls")
	}
	return strings.ToUpper(s)
}

func reportedCountry(country string) string {
	cc := strings.ToUpper(strings.TrimSpace(country))
	if len(cc) == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
		return cc
	}
	return ""
}

func stripHostPort(ip string) string {
	trimmed := strings.TrimSpace(ip)
	if strings.Count(trimmed, ":") == 1 {
		return trimmed[:strings.Index(trimmed, ":")]
	}
	return trimmed
}

type fluxLocationEntry struct {
	IP string `json:"ip"`
}

func fetchFluxLocations(ctx context.Context, spec string, nodes []string) []string {
	urls := []string{fluxAPI + "/apps/location/" + spec}
	for _, node := range nodes {
		urls = append(urls, fmt.Sprintf("http://%s:%d/apps/location/%s", node, fluxNodePort, spec))
	}
	var (
		mu  sync.Mutex
		ips []string
		wg  sync.WaitGroup
	)
	for _, endpoint := range urls {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, locationTimeout)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return
			}
			res, err := httpClient.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close()
			var body struct {
				Data []fluxLocationEntry `json:"data"`
			}
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				return
			}
			var found []string
			for _, e := range body.Data {
				if ip := stripHostPort(e.IP); ip != "" {
					found = append(found, ip)
				}
			}
			mu.Lock()
			ips = append(ips, found...)
			mu.Unlock()
		}(endpoint)
	}
	wg.Wait()
	return ips
}

func probeGateway(ctx context.Context, ip string) *GatewayInfo {
	controlURL := fmt.Sprintf("http://%s:%d", ip, controlPort)
	res, err := fetchSigned(ctx, controlURL+"/v1/info", http.MethodGet, nil, "", discoveryTimeout)
	if err != nil {
		return nil
	}
	var info InfoResponse
	if err := json.Unmarshal(res.Data, &info); err != nil {
		return nil
	}
	return &GatewayInfo{InfoResponse: info, IP: ip, ControlURL: controlURL}
}

// discoverFleet resolves reachable, signature-verified gateways from Flux.
func discoverFleet(ctx context.Context, specs, nodes []string) ([]GatewayInfo, error) {
	ipCountry := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, spec := range specs {
		wg.Add(1)
		go func(spec string) {
			defer wg.Done()
			cc := specToCountryCode(spec)
			for _, ip := range fetchFluxLocations(ctx, spec, nodes) {
				mu.Lock()
				if _, ok := ipCountry[ip]; !ok {
					ipCountry[ip] = cc
				}
				mu.Unlock()
			}
		}(spec)
	}
	wg.Wait()
	if len(ipCountry) == 0 {
		return nil, errors.New("no gateways found on the Flux network")
	}

	candidates := make([]string, 0, len(ipCountry))
	for ip := range ipCountry {
		candidates = append(candidates, ip)
	}
	results := make([]*GatewayInfo, len(candidates))
	var probeWG sync.WaitGroup
	for i, ip := range candidates {
		probeWG.Add(1)
		go func(i int, ip string) {
			defer probeWG.Done()
			results[i] = probeGateway(ctx, ip)
		}(i, ip)
	}
	probeWG.Wait()

	var gateways []GatewayInfo
	for _, g := range results {
		if g == nil {
			continue
		}
		if cc := reportedCountry(g.Country); cc != "" {
			g.Country = cc
		} else {
			g.Country = ipCountry[g.IP]
		}
		gateways = append(gateways, *g)
	}
	sort.Slice(gateways, func(i, j int) bool {
		if gateways[i].Country != gateways[j].Country {
			return gateways[i].Country < gateways[j].Country
		}
		return gateways[i].Load < gateways[j].Load
	})
	if len(gateways) == 0 {
		return nil, errors.New("no reachable gateways (every /v1/info probe failed)")
	}
	return gateways, nil
}

// ---- enroll / status -------------------------------------------------------

func enrollAt(ctx context.Context, gatewayIP, publicKeyB64, signPubKey string) (EnrollResponse, error) {
	nonce := solvePoW(publicKeyB64, powBits)
	body, _ := json.Marshal(map[string]string{"pubkey": publicKeyB64, "pow_nonce": nonce})
	res, err := fetchSigned(ctx, fmt.Sprintf("http://%s:%d/v1/enroll", gatewayIP, controlPort), http.MethodPost, body, signPubKey, enrollRequestTime)
	if err != nil {
		return EnrollResponse{}, err
	}
	var out EnrollResponse
	if err := json.Unmarshal(res.Data, &out); err != nil {
		return EnrollResponse{}, err
	}
	return out, nil
}

// ---- latency / quality -----------------------------------------------------

func measureLatency(ctx context.Context, gw GatewayInfo) *int64 {
	var rtts []int64
	for i := 0; i < pingSamples; i++ {
		sctx, cancel := context.WithTimeout(ctx, pingSampleTimeout)
		started := time.Now()
		req, err := http.NewRequestWithContext(sctx, http.MethodGet, gw.ControlURL+"/v1/info", nil)
		if err == nil {
			if res, err := httpClient.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode == http.StatusOK {
					rtts = append(rtts, time.Since(started).Milliseconds())
				}
			}
		}
		cancel()
	}
	if len(rtts) == 0 {
		return nil
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	ms := rtts[len(rtts)/2]
	return &ms
}

type GatewayQuality struct {
	Tone    string
	Label   string
	LoadPct int
	Score   int
}

func gatewayQuality(latencyMs *int64, load float64) GatewayQuality {
	l := load
	if l < 0 {
		l = 0
	}
	if l > 1 {
		l = 1
	}
	loadPct := int(l*100 + 0.5)
	loadScore := 1 - l
	latScore := 0.5
	if latencyMs != nil {
		switch ms := *latencyMs; {
		case ms <= 60:
			latScore = 1
		case ms >= 400:
			latScore = 0
		default:
			latScore = 1 - float64(ms-60)/340
		}
	}
	score := int((0.6*loadScore+0.4*latScore)*100 + 0.5)
	tone := "fair"
	if l >= 0.85 {
		tone = "busy"
	} else if score >= 78 {
		tone = "excellent"
	} else if score >= 55 {
		tone = "good"
	}
	labels := map[string]string{"excellent": "Excellent", "good": "Good", "fair": "Fair", "busy": "Busy"}
	return GatewayQuality{Tone: tone, Label: labels[tone], LoadPct: loadPct, Score: score}
}

// ---- transports ------------------------------------------------------------

var implementedTransports = map[string]bool{"wg": true, "awg": true, "wg-tls": true}

var transportPreference = map[string][]string{
	"speed":   {"wg", "awg"},
	"auto":    {"wg", "awg", "wg-tls"},
	"stealth": {"wg-tls", "awg"},
}

func advertisedOrLegacy(ts []Transport) []Transport {
	if len(ts) > 0 {
		return ts
	}
	return []Transport{{Type: "wg", Port: wgPort}}
}

func transportChain(transports []Transport, mode string) []Transport {
	order := transportPreference[mode]
	var out []Transport
	for _, t := range advertisedOrLegacy(transports) {
		if !implementedTransports[t.Type] || t.Port < 1 || t.Port > 65535 {
			continue
		}
		found := false
		for _, allowed := range order {
			if t.Type == allowed {
				found = true
				break
			}
		}
		if found {
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return indexOf(order, out[i].Type) < indexOf(order, out[j].Type)
	})
	return out
}

func indexOf(list []string, value string) int {
	for i, v := range list {
		if v == value {
			return i
		}
	}
	return len(list)
}

// requireTransport returns the ordered chain or an error that never silently
// downgrades Stealth to plain WireGuard.
func requireTransport(transports []Transport, mode string) ([]Transport, error) {
	chain := transportChain(transports, mode)
	if len(chain) > 0 {
		return chain, nil
	}
	if mode == "stealth" {
		return nil, errors.New("Stealth mode: this location offers no DPI-resistant transport; pick another location, or turn off Stealth mode")
	}
	return nil, errors.New("this location offers no transport compatible with the selected mode")
}

// ---- DNS choice ------------------------------------------------------------

type dnsOption struct {
	ID       string
	Provider string
	Blurb    string
	Servers  []string
}

var dnsOptions = []dnsOption{
	{"cloudflare", "Cloudflare", "Fast, no filtering", []string{"1.1.1.1", "1.0.0.1"}},
	{"google", "Google Public DNS", "No filtering", []string{"8.8.8.8", "8.8.4.4"}},
	{"quad9", "Quad9", "Blocks known malicious sites", []string{"9.9.9.9", "149.112.112.112"}},
	{"dns4eu", "DNS4EU", "EU-based, blocks malware and phishing", []string{"86.54.11.1", "86.54.11.201"}},
	{"adguard", "AdGuard DNS", "Blocks ads and trackers", []string{"94.140.14.14", "94.140.15.15"}},
	{"family", "Cloudflare for Families", "Blocks malware and adult content", []string{"1.1.1.3", "1.0.0.3"}},
}

const defaultDNS = "cloudflare"

func parseDNSChoice(value string) string {
	for _, o := range dnsOptions {
		if o.ID == value {
			return value
		}
	}
	if value == "mullvad" {
		return "quad9"
	}
	return defaultDNS
}

func dnsServersFor(choice, gatewayDNS string) []netip.Addr {
	if choice == defaultDNS {
		return parseDNSServers(gatewayDNS)
	}
	for _, o := range dnsOptions {
		if o.ID == choice {
			var out []netip.Addr
			for _, s := range o.Servers {
				if a, err := netip.ParseAddr(s); err == nil {
					out = append(out, a)
				}
			}
			return out
		}
	}
	return parseDNSServers(gatewayDNS)
}

func parseDNSServers(value string) []netip.Addr {
	var out []netip.Addr
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		out = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return out
}

// ---- small formatting helpers ---------------------------------------------

func publicIP(ip string) net.IP {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return net.IP(addr.AsSlice())
}
