package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- list ------------------------------------------------------------------

func listCommand(args []string) int {
	locations := false
	asJSON := false
	noLatency := false
	for _, a := range args {
		switch a {
		case "--locations", "--cities", "-L":
			locations = true
		case "--json":
			asJSON = true
		case "--no-latency", "--fast":
			noLatency = true
		case "--countries":
			locations = false
		default:
			fmt.Fprintf(os.Stderr, "fluxcore: unknown list flag %q\n", a)
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	up, err := parseUpstream(cfg.Upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 2
	}
	configureHTTPClient(up)
	gateways, err := discoverFleetFrom(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	latency := map[string]int64{}
	if cache, err := loadFleetCache(); err == nil {
		latency = cache.LatencyMs
	}

	var rows []Country
	if locations {
		rows = groupByLocation(gateways, latency)
	} else {
		rows = groupByCountry(gateways, latency)
	}
	if !noLatency {
		measured := measureFleetLatencies(gateways, groupByCountry(gateways, nil), groupByLocation(gateways, nil))
		for ip, ms := range measured {
			latency[ip] = ms
		}
		if locations {
			rows = groupByLocation(gateways, latency)
		} else {
			rows = groupByCountry(gateways, latency)
		}
		saveFleetCache(gateways, latency)
	}

	if asJSON {
		type row struct {
			ID      string `json:"id"`
			Code    string `json:"code"`
			Name    string `json:"name"`
			City    string `json:"city,omitempty"`
			Nodes   int    `json:"nodes"`
			Latency *int64 `json:"latencyMs,omitempty"`
			Load    int    `json:"loadPct"`
			Tone    string `json:"tone"`
		}
		out := make([]row, 0, len(rows))
		for _, r := range rows {
			q := gatewayQuality(r.LatencyMs, r.Best.Load)
			out = append(out, row{r.ID, r.Code, r.Name, r.City, r.NodeCount, r.LatencyMs, q.LoadPct, q.Tone})
		}
		return jsonOut(out)
	}

	if len(rows) == 0 {
		fmt.Println("no gateways")
		return 1
	}
	fmt.Printf("%-3s %-22s %-18s %5s %6s %5s %4s\n", "", "COUNTRY", "CITY", "NODES", "PING", "LOAD", "SEEN")
	for _, r := range rows {
		ping := "—"
		if r.LatencyMs != nil {
			ping = fmt.Sprintf("%dms", *r.LatencyMs)
		}
		q := gatewayQuality(r.LatencyMs, r.Best.Load)
		fmt.Printf("%-3s %-22s %-18s %5d %6s %4d%% %4s\n",
			r.Flag, truncate(r.Name, 22), truncate(r.City, 18), r.NodeCount, ping, q.LoadPct, q.Tone)
	}
	fmt.Println()
	if locations {
		fmt.Println("pick one with --country CODE:CITY (e.g. --country us:new york)")
	} else {
		fmt.Println("pick one with --country CODE or `fluxcore config set country CODE`")
	}
	return 0
}

func discoverFleetFrom(ctx context.Context) ([]GatewayInfo, error) {
	specs, err := bundledSpecs()
	if err != nil {
		return nil, err
	}
	nodes := bundledSeedNodes()
	if dir, err := loadBundledDirectory(); err == nil {
		nodes = append(nodes, directorySeedIPs(dir)...)
	}
	gateways, err := discoverFleet(ctx, specs, nodes)
	if err == nil {
		return gateways, nil
	}
	if cache, cacheErr := loadFleetCache(); cacheErr == nil && len(cache.Gateways) > 0 {
		fmt.Fprintf(os.Stderr, "discovery failed (%v); using cached fleet\n", err)
		return cache.Gateways, nil
	}
	return nil, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ---- dns -------------------------------------------------------------------

func dnsCommand(args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	if len(args) == 0 || args[0] == "list" {
		fmt.Printf("current: %s\n\n", cfg.DNS)
		for _, o := range dnsOptions {
			marker := " "
			if o.ID == cfg.DNS {
				marker = "*"
			}
			fmt.Printf("%s %-12s %-26s %-38s %s\n", marker, o.ID, o.Provider, o.Blurb, strings.Join(o.Servers, ", "))
		}
		fmt.Println("\"cloudflare\" means the gateway's own resolver; the others are used directly inside the tunnel.")
		return 0
	}
	switch args[0] {
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore dns set <id>")
			return 2
		}
		id := strings.ToLower(args[1])
		if parseDNSChoice(id) != id {
			fmt.Fprintf(os.Stderr, "fluxcore: unknown DNS provider %q\n", id)
			return 2
		}
		cfg.DNS = id
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 1
		}
		fmt.Printf("dns set to %s\n", id)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: fluxcore dns [list | set ID]")
		return 2
	}
}

// ---- split -----------------------------------------------------------------

func splitCommand(args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	if len(args) == 0 || args[0] == "show" {
		printSplit(cfg.Split)
		return 0
	}
	changed := true
	switch args[0] {
	case "mode":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore split mode off|include|exclude")
			return 2
		}
		cfg.Split.Mode = strings.ToLower(args[1])
	case "add":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore split add <domain|cidr> <value>")
			return 2
		}
		rule, err := normalizeSplitRule(args[1], args[2], "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 2
		}
		cfg.Split.Rules = append(cfg.Split.Rules, rule)
		fmt.Printf("added %s %s\n", rule.Kind, rule.Value)
		if cfg.Split.Mode == "off" {
			cfg.Split.Mode = "include"
			fmt.Println("split mode was off; now include (only matched traffic uses the tunnel)")
		}
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore split remove <index|value>")
			return 2
		}
		idx, err := strconv.Atoi(args[1])
		if err == nil {
			if idx < 1 || idx > len(cfg.Split.Rules) {
				fmt.Fprintf(os.Stderr, "fluxcore: no rule %d\n", idx)
				return 2
			}
			cfg.Split.Rules = append(cfg.Split.Rules[:idx-1], cfg.Split.Rules[idx:]...)
		} else {
			kept := cfg.Split.Rules[:0]
			removed := false
			for _, r := range cfg.Split.Rules {
				if strings.EqualFold(r.Value, args[1]) {
					removed = true
					continue
				}
				kept = append(kept, r)
			}
			if !removed {
				fmt.Fprintf(os.Stderr, "fluxcore: no rule matches %q\n", args[1])
				return 2
			}
			cfg.Split.Rules = kept
		}
		fmt.Println("removed")
	case "clear":
		cfg.Split.Rules = []SplitRule{}
		cfg.Split.Mode = "off"
		fmt.Println("split rules cleared")
	case "lan":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore split lan on|off")
			return 2
		}
		v, err := parseBool(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 2
		}
		cfg.Split.LANBypass = v
		fmt.Printf("LAN bypass %v\n", v)
	case "dns":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore split dns tunnel|system")
			return 2
		}
		v := strings.ToLower(args[1])
		if v != "tunnel" && v != "system" {
			fmt.Fprintln(os.Stderr, "fluxcore: expected tunnel or system")
			return 2
		}
		cfg.Split.ExcludedDNS = v
		fmt.Printf("split DNS %s\n", v)
	default:
		fmt.Fprintln(os.Stderr, "usage: fluxcore split [show | mode M | add KIND VALUE | remove IDX | clear | lan on|off | dns tunnel|system]")
		return 2
	}
	if !changed {
		return 0
	}
	if _, err := normalizeSplitPolicy(cfg.Split); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 2
	}
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	return 0
}

func printSplit(p SplitPolicy) {
	fmt.Printf("mode       %s\n", p.Mode)
	fmt.Printf("LAN bypass %v\n", p.LANBypass)
	fmt.Printf("split DNS  %s\n", p.ExcludedDNS)
	if len(p.Rules) == 0 {
		fmt.Println("rules      (none)")
		return
	}
	fmt.Println("rules")
	for i, r := range p.Rules {
		state := "on"
		if !ruleEnabled(r) {
			state = "off"
		}
		fmt.Printf("  %2d  %-6s %-32s %s\n", i+1, r.Kind, r.Value, state)
	}
	fmt.Println()
	fmt.Println("include = only matched traffic uses the tunnel; exclude = matched traffic goes direct.")
}

// ---- favorites -------------------------------------------------------------

func favoritesCommand(args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	if len(args) == 0 || args[0] == "list" {
		if len(cfg.Favorites) == 0 {
			fmt.Println("no favorites yet (add with `fluxcore favorites add de` or `add us:new york`)")
			return 0
		}
		for i, f := range cfg.Favorites {
			fmt.Printf("%2d  %s\n", i+1, f)
		}
		return 0
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore favorites add CODE[:CITY]")
			return 2
		}
		f := strings.TrimSpace(strings.Join(args[1:], " "))
		code, _ := normalizeCountrySelector(f)
		if code == "" {
			fmt.Fprintf(os.Stderr, "fluxcore: invalid location %q\n", f)
			return 2
		}
		for _, existing := range cfg.Favorites {
			if strings.EqualFold(existing, f) {
				fmt.Println("already a favorite")
				return 0
			}
		}
		cfg.Favorites = append(cfg.Favorites, f)
		fmt.Printf("added %s\n", f)
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore favorites remove CODE[:CITY]")
			return 2
		}
		f := strings.Join(args[1:], " ")
		kept := cfg.Favorites[:0]
		for _, existing := range cfg.Favorites {
			if !strings.EqualFold(existing, f) {
				kept = append(kept, existing)
			}
		}
		if len(kept) == len(cfg.Favorites) {
			fmt.Fprintf(os.Stderr, "fluxcore: %q is not a favorite\n", f)
			return 2
		}
		cfg.Favorites = kept
		fmt.Println("removed")
	case "clear":
		cfg.Favorites = []string{}
		fmt.Println("favorites cleared")
	default:
		fmt.Fprintln(os.Stderr, "usage: fluxcore favorites [list | add LOC | remove LOC | clear]")
		return 2
	}
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	return 0
}
