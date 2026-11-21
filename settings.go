package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---- config file -----------------------------------------------------------

const appDirName = "fluxcore"

// legacyAppDirName is the config directory used before the rename to Fluxcore.
// It is migrated once so an existing identity and settings are not lost.
const legacyAppDirName = "cumulusvpn"

// Config is the persisted CLI state, with defaults applied on load.
type Config struct {
	Keypair        *Keypair    `json:"keypair,omitempty"`
	Country        string      `json:"country"`
	RouteStyle     string      `json:"routeStyle"`    // "single" | "multihop"
	TransportMode  string      `json:"transportMode"` // "auto" | "stealth" | "speed"
	Entry          string      `json:"entry"`
	Exit           string      `json:"exit"`
	KillSwitch     bool        `json:"killSwitch"`
	NodeDiversity  bool        `json:"nodeDiversity"`
	Favorites      []string    `json:"favorites"`
	DNS            string      `json:"dns"`
	Listen         string      `json:"listen"`
	HTTPListen     string      `json:"httpListen"`
	AutoReconnect  bool        `json:"autoReconnect"`
	IdentityBackup bool        `json:"identityBackup"`
	Upstream       string      `json:"upstream"` // proxy URL, empty means direct
	Split          SplitPolicy `json:"split"`
}

func defaultConfig() Config {
	return Config{
		RouteStyle:     "single",
		TransportMode:  "auto",
		KillSwitch:     true,
		Favorites:      []string{},
		DNS:            defaultDNS,
		Listen:         "127.0.0.1:1080",
		HTTPListen:     "127.0.0.1:1081",
		AutoReconnect:  true,
		IdentityBackup: true,
		Split:          defaultSplitPolicy(),
	}
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, appDirName)
	if _, err := os.Stat(dir); err == nil {
		return dir, nil
	}
	// One-time migration from the pre-rename config directory.
	legacy := filepath.Join(base, legacyAppDirName)
	if _, err := os.Stat(legacy); err == nil {
		if err := os.Rename(legacy, dir); err == nil {
			return dir, nil
		}
	}
	return dir, nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func backupPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.backup"), nil
}

func cachePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "fleet-cache.json"), nil
}

func loadConfig() (Config, error) {
	cfg := defaultConfig()
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalize()
	return cfg, nil
}

func (c *Config) normalize() {
	if c.RouteStyle != "multihop" {
		c.RouteStyle = "single"
	}
	switch c.TransportMode {
	case "stealth", "speed", "auto":
	default:
		c.TransportMode = "auto"
	}
	c.DNS = parseDNSChoice(c.DNS)
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = "127.0.0.1:1080"
	}
	if strings.TrimSpace(c.HTTPListen) == "" {
		c.HTTPListen = "127.0.0.1:1081"
	}
	if c.Favorites == nil {
		c.Favorites = []string{}
	}
	c.Upstream = strings.TrimSpace(c.Upstream)
	if p, err := normalizeSplitPolicy(c.Split); err == nil {
		c.Split = p
	} else {
		c.Split = defaultSplitPolicy()
	}
}

func saveConfig(cfg Config) error {
	cfg.normalize()
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ensureIdentity installs the persisted keypair, or restores the backup, or
// mints a fresh one. Android behavior: the backup is authoritative on a fresh
// install so the same pubkey keeps its entitlement.
func ensureIdentity(cfg *Config) error {
	if cfg.Keypair != nil && cfg.Keypair.PrivateKey != "" {
		if cfg.Keypair.PublicKey == "" {
			kp, err := keypairFromPrivate(cfg.Keypair.PrivateKey)
			if err != nil {
				return err
			}
			cfg.Keypair = &kp
		}
		if cfg.IdentityBackup {
			return writeIdentityBackup(cfg.Keypair.PrivateKey)
		}
		return nil
	}
	if cfg.IdentityBackup {
		if kp, err := readIdentityBackup(); err == nil {
			cfg.Keypair = &kp
			return saveConfig(*cfg)
		}
	}
	kp, err := generateKeypair()
	if err != nil {
		return err
	}
	cfg.Keypair = &kp
	if err := saveConfig(*cfg); err != nil {
		return err
	}
	if cfg.IdentityBackup {
		return writeIdentityBackup(kp.PrivateKey)
	}
	return nil
}

func writeIdentityBackup(privateKeyB64 string) error {
	path, err := backupPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	key, err := encodeRecoveryKey(privateKeyB64)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(key+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readIdentityBackup() (Keypair, error) {
	path, err := backupPath()
	if err != nil {
		return Keypair{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Keypair{}, err
	}
	return decodeRecoveryKey(string(raw))
}

func identityBackupExists() bool {
	path, err := backupPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// ---- fleet cache -----------------------------------------------------------

type fleetCache struct {
	Gateways  []GatewayInfo    `json:"gateways"`
	LatencyMs map[string]int64 `json:"latencyMs"`
	SavedAt   int64            `json:"savedAt"`
}

func saveFleetCache(gateways []GatewayInfo, latency map[string]int64) {
	path, err := cachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	raw, err := json.MarshalIndent(fleetCache{Gateways: gateways, LatencyMs: latency, SavedAt: time.Now().UnixMilli()}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

func loadFleetCache() (fleetCache, error) {
	var cache fleetCache
	path, err := cachePath()
	if err != nil {
		return cache, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cache, err
	}
	err = json.Unmarshal(raw, &cache)
	if cache.LatencyMs == nil {
		cache.LatencyMs = map[string]int64{}
	}
	return cache, err
}

// ---- validation helpers ----------------------------------------------------

func validateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("invalid listen address %q: missing port", addr)
	}
	if host == "" {
		return fmt.Errorf("refusing to listen on all interfaces; bind 127.0.0.1 explicitly")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address must be loopback (127.0.0.1), got %q", host)
	}
	return nil
}

func normalizeCountrySelector(value string) (code, city string) {
	v := strings.TrimSpace(value)
	if v == "" || strings.EqualFold(v, "auto") || strings.EqualFold(v, "fastest") {
		return "", ""
	}
	parts := strings.SplitN(v, ":", 2)
	code = strings.ToUpper(strings.TrimSpace(parts[0]))
	if len(parts) == 2 {
		city = strings.TrimSpace(parts[1])
	}
	return code, city
}

func isNumericIP(host string) bool {
	return net.ParseIP(host) != nil
}
