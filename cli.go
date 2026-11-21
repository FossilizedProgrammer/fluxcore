package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// version can be overridden at build time with
// -ldflags "-X main.version=<tag>" so released binaries report their tag.
var version = "0.2.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return runCommand(nil)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run", "connect", "start":
		return runCommand(rest)
	case "list", "countries", "locations":
		return listCommand(rest)
	case "status":
		return statusCommand(rest)
	case "config", "settings":
		return configCommand(rest)
	case "identity", "id":
		return identityCommand(rest)
	case "dns":
		return dnsCommand(rest)
	case "split", "split-tunnel":
		return splitCommand(rest)
	case "favorites", "fav":
		return favoritesCommand(rest)
	case "version", "--version", "-V":
		fmt.Printf("fluxcore %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-h":
		printUsage()
		return 0
	default:
		// Bare flags mean "run", so `fluxcore --country DE` works.
		if strings.HasPrefix(cmd, "-") {
			return runCommand(args)
		}
		fmt.Fprintf(os.Stderr, "fluxcore: unknown command %q\n\n", cmd)
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Print(`Fluxcore CLI — local SOCKS5/HTTP proxy over the Fluxcore fleet.
No TUN device, no root, no system routes: apps opt in by pointing at the proxy.

USAGE
  fluxcore [run] [flags]        start the proxy (default command)
  fluxcore list [--locations]   countries or cities, with latency
  fluxcore status               show the running session
  fluxcore config [get|set]     view or change saved settings
  fluxcore identity [...]       show keys, recovery key, import
  fluxcore dns [list|set ID]    choose the DNS resolver used in the tunnel
  fluxcore split [...]          split tunneling rules
  fluxcore favorites [...]      saved locations
  fluxcore version

RUN FLAGS
  -c, --country CODE[:CITY]   pick a country (or city) instead of the fastest
      --entry CODE[:CITY]     multi-hop entry hop (implies --multihop)
      --exit CODE[:CITY]      multi-hop exit hop (implies --multihop)
      --multihop              nested WireGuard: entry sees the exit, exit sees
                              your destination, neither sees both
      --stealth               prefer DPI-resistant transports (wg-tls/awg)
      --speed                 prefer plain WireGuard
      --auto                  let the client choose a transport
      --upstream URL          dial everything through an upstream proxy
                              (socks5:// or http://, default port if omitted)
      --no-upstream           ignore the saved upstream for this run
  -l, --listen ADDR           SOCKS5 listener (loopback; default 127.0.0.1:1080)
      --http-listen ADDR      HTTP listener (loopback; default 127.0.0.1:1081)
      --no-kill-switch        allow direct fallback if the tunnel is down
      --no-reconnect          exit when the tunnel drops instead of retrying
  -v, --verbose               log proxy and WireGuard activity

SETTINGS live in ` + configLocationHint() + `.
Point a browser or app at socks5://127.0.0.1:1080 or http://127.0.0.1:1081.
`)
}

// ---- status ----------------------------------------------------------------

func statusCommand(args []string) int {
	st, err := loadRuntimeState()
	if err != nil {
		fmt.Println("not running (no session state; start it with `fluxcore run`)")
		return 1
	}
	if st.HTTPListen == "" {
		st.HTTPListen = "127.0.0.1:1081"
	}
	listeners := []struct{ label, addr string }{
		{"socks5", st.Listen},
		{"http", st.HTTPListen},
	}
	for _, listener := range listeners {
		c, err := net.DialTimeout("tcp", listener.addr, 800*time.Millisecond)
		if err != nil {
			fmt.Printf("stale session state for %s listener %s: not listening (the process exited)\n", listener.label, listener.addr)
			clearRuntimeState()
			return 1
		}
		_ = c.Close()
	}
	fmt.Println("running")
	fmt.Printf("  socks5     %s\n", st.Listen)
	fmt.Printf("  http       %s\n", st.HTTPListen)
	if st.Exit.IP != "" {
		fmt.Printf("  route      multihop %s %s → %s %s\n", st.Entry.Flag, st.Entry.Name, st.Exit.Flag, st.Exit.Name)
	} else {
		fmt.Printf("  route      single → %s %s (%s)\n", st.Entry.Flag, st.Entry.Name, st.Entry.City)
	}
	fmt.Printf("  transport  %s\n", st.Transport)
	fmt.Printf("  local IP   %s\n", st.AssignedIP)
	fmt.Printf("  uptime     %s\n", time.Since(time.Unix(st.Since, 0)).Round(time.Second))
	fmt.Printf("  traffic    ↓ %s  ↑ %s\n", humanBytes(st.RxBytes), humanBytes(st.TxBytes))
	if st.LastHs > 0 {
		fmt.Printf("  handshake  %s ago\n", time.Since(time.Unix(st.LastHs, 0)).Round(time.Second))
	}
	return 0
}

// ---- config ----------------------------------------------------------------

func configLocationHint() string {
	path, err := configPath()
	if err != nil {
		return "the user config directory"
	}
	return path
}

func configCommand(args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	if len(args) == 0 {
		printConfig(cfg)
		return 0
	}
	switch args[0] {
	case "path":
		fmt.Println(configLocationHint())
		return 0
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore config get <key>")
			return 2
		}
		v, ok := configValue(cfg, args[1])
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown setting %q\n", args[1])
			return 2
		}
		fmt.Println(v)
		return 0
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore config set <key> <value>")
			return 2
		}
		if err := configSet(&cfg, args[1], strings.Join(args[2:], " ")); err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 2
		}
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 1
		}
		fmt.Println("saved")
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: fluxcore config [get KEY | set KEY VALUE | path]")
		return 2
	}
}

func printConfig(cfg Config) {
	pub := ""
	if cfg.Keypair != nil {
		pub = cfg.Keypair.PublicKey
	}
	fmt.Printf("country         %s\n", displaySelector(cfg.Country))
	fmt.Printf("route           %s\n", cfg.RouteStyle)
	fmt.Printf("transport       %s\n", cfg.TransportMode)
	fmt.Printf("entry           %s\n", displaySelector(cfg.Entry))
	fmt.Printf("exit            %s\n", displaySelector(cfg.Exit))
	fmt.Printf("socks5 listen   %s\n", cfg.Listen)
	fmt.Printf("http listen     %s\n", cfg.HTTPListen)
	fmt.Printf("dns             %s\n", cfg.DNS)
	fmt.Printf("kill switch     %v\n", cfg.KillSwitch)
	fmt.Printf("auto reconnect  %v\n", cfg.AutoReconnect)
	fmt.Printf("node diversity  %v\n", cfg.NodeDiversity)
	fmt.Printf("identity backup %v\n", cfg.IdentityBackup)
	fmt.Printf("upstream        %s\n", displayUpstream(cfg.Upstream))
	fmt.Printf("split mode      %s\n", cfg.Split.Mode)
	fmt.Printf("public key      %s\n", pub)
	fmt.Printf("config file     %s\n", configLocationHint())
}

func configValue(cfg Config, key string) (string, bool) {
	switch strings.ToLower(key) {
	case "country":
		return cfg.Country, true
	case "route", "route-style":
		return cfg.RouteStyle, true
	case "transport", "transport-mode":
		return cfg.TransportMode, true
	case "entry":
		return cfg.Entry, true
	case "exit":
		return cfg.Exit, true
	case "listen", "socks-listen":
		return cfg.Listen, true
	case "http-listen":
		return cfg.HTTPListen, true
	case "dns":
		return cfg.DNS, true
	case "kill-switch":
		return fmt.Sprint(cfg.KillSwitch), true
	case "reconnect", "auto-reconnect":
		return fmt.Sprint(cfg.AutoReconnect), true
	case "diversity", "node-diversity":
		return fmt.Sprint(cfg.NodeDiversity), true
	case "identity-backup":
		return fmt.Sprint(cfg.IdentityBackup), true
	case "upstream":
		return cfg.Upstream, true
	}
	return "", false
}

func configSet(cfg *Config, key, value string) error {
	switch strings.ToLower(key) {
	case "country":
		code, city := normalizeCountrySelector(value)
		if value != "" && code == "" {
			return fmt.Errorf("invalid country %q", value)
		}
		cfg.Country = strings.TrimSpace(value)
		_ = city
	case "route", "route-style":
		if value != "single" && value != "multihop" {
			return fmt.Errorf("route must be single or multihop")
		}
		cfg.RouteStyle = value
	case "transport", "transport-mode":
		switch value {
		case "auto", "stealth", "speed":
			cfg.TransportMode = value
		default:
			return fmt.Errorf("transport must be auto, stealth or speed")
		}
	case "entry":
		cfg.Entry = strings.TrimSpace(value)
	case "exit":
		cfg.Exit = strings.TrimSpace(value)
	case "listen", "socks-listen":
		if err := validateListen(value); err != nil {
			return err
		}
		if value == cfg.HTTPListen {
			return fmt.Errorf("SOCKS5 and HTTP listeners must use different addresses")
		}
		cfg.Listen = value
	case "http-listen":
		if err := validateListen(value); err != nil {
			return err
		}
		if value == cfg.Listen {
			return fmt.Errorf("SOCKS5 and HTTP listeners must use different addresses")
		}
		cfg.HTTPListen = value
	case "dns":
		if parseDNSChoice(value) != value {
			return fmt.Errorf("unknown DNS provider %q (see `fluxcore dns`)", value)
		}
		cfg.DNS = value
	case "kill-switch":
		v, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.KillSwitch = v
	case "reconnect", "auto-reconnect":
		v, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.AutoReconnect = v
	case "diversity", "node-diversity":
		v, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.NodeDiversity = v
	case "identity-backup":
		v, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.IdentityBackup = v
	case "upstream":
		v := strings.TrimSpace(value)
		if v == "" || strings.EqualFold(v, "off") || strings.EqualFold(v, "none") {
			cfg.Upstream = ""
			return nil
		}
		up, err := parseUpstream(v)
		if err != nil {
			return err
		}
		cfg.Upstream = up.proxyURL.String()
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("expected on or off, got %q", value)
}

// ---- identity --------------------------------------------------------------

func identityCommand(args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	if err := ensureIdentity(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show", "status":
		fmt.Printf("public key     %s\n", cfg.Keypair.PublicKey)
		fmt.Printf("backup         %v (%s)\n", identityBackupExists(), backupLocation())
		fmt.Printf("config file    %s\n", configLocationHint())
		return 0
	case "recovery", "export-key":
		key, err := encodeRecoveryKey(cfg.Keypair.PrivateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "This key is your identity. Anyone who has it can connect as you.")
		fmt.Println(key)
		return 0
	case "import", "restore":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fluxcore identity import <recovery-key>")
			return 2
		}
		kp, err := decodeRecoveryKey(strings.Join(args[1:], " "))
		if err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 1
		}
		cfg.Keypair = &kp
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
			return 1
		}
		if cfg.IdentityBackup {
			_ = writeIdentityBackup(kp.PrivateKey)
		}
		fmt.Printf("imported %s\n", kp.PublicKey)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: fluxcore identity [show | recovery | import KEY]")
		return 2
	}
}

func backupLocation() string {
	path, err := backupPath()
	if err != nil {
		return "unknown"
	}
	return path
}

// jsonOut prints an indented JSON document.
func jsonOut(v any) int {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fluxcore: %v\n", err)
		return 1
	}
	fmt.Println(string(raw))
	return 0
}
