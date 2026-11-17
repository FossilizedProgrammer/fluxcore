package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// ---- persisted split-tunnel policy ----------------------------------------

// SplitRule is one user rule. Values are normalized on save.
type SplitRule struct {
	Kind    string `json:"kind"` // "domain" | "cidr"
	Value   string `json:"value"`
	Label   string `json:"label,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// SplitPolicy is the on-disk policy. Rules are evaluated on the client; the
// gateway never learns them.
type SplitPolicy struct {
	Version     int         `json:"version"`
	Mode        string      `json:"mode"` // "off" | "include" | "exclude"
	Rules       []SplitRule `json:"rules"`
	LANBypass   bool        `json:"lanBypass"`
	ExcludedDNS string      `json:"excludedDns"` // "tunnel" | "system"
}

func defaultSplitPolicy() SplitPolicy {
	return SplitPolicy{Version: 1, Mode: "off", Rules: []SplitRule{}, LANBypass: false, ExcludedDNS: "tunnel"}
}

func ruleEnabled(r SplitRule) bool {
	return r.Enabled == nil || *r.Enabled
}

// normalizeSplitRule validates and canonicalizes a rule.
func normalizeSplitRule(kind, value, label string) (SplitRule, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if value == "" {
		return SplitRule{}, fmt.Errorf("empty %s rule", kind)
	}
	switch kind {
	case "domain":
		v := strings.ToLower(value)
		wildcard := strings.HasPrefix(v, "*.") || strings.HasPrefix(v, ".")
		v = strings.TrimPrefix(v, "*.")
		v = strings.TrimPrefix(v, ".")
		v = strings.TrimSuffix(v, ".")
		if v == "" || strings.ContainsAny(v, "/:@ *") {
			return SplitRule{}, fmt.Errorf("invalid domain %q", value)
		}
		if _, err := netip.ParseAddr(v); err == nil {
			return SplitRule{}, fmt.Errorf("invalid domain %q (that is an IP address; use a cidr rule)", value)
		}
		if wildcard {
			v = "*." + v
		}
		return SplitRule{Kind: "domain", Value: v, Label: label}, nil
	case "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return SplitRule{}, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return SplitRule{}, fmt.Errorf("refusing CIDR %q: it would route the whole internet", value)
		}
		return SplitRule{Kind: "cidr", Value: prefix.String(), Label: label}, nil
	default:
		return SplitRule{}, fmt.Errorf("unknown split rule kind %q (want domain or cidr)", kind)
	}
}

// normalizeSplitPolicy validates an entire policy and canonicalizes its rules.
func normalizeSplitPolicy(p SplitPolicy) (SplitPolicy, error) {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Mode == "" {
		p.Mode = "off"
	}
	switch p.Mode {
	case "off", "include", "exclude":
	default:
		return p, fmt.Errorf("invalid split mode %q (want off, include or exclude)", p.Mode)
	}
	if p.ExcludedDNS == "" {
		p.ExcludedDNS = "tunnel"
	}
	if p.ExcludedDNS != "tunnel" && p.ExcludedDNS != "system" {
		return p, fmt.Errorf("invalid excludedDns %q (want tunnel or system)", p.ExcludedDNS)
	}
	out := make([]SplitRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		n, err := normalizeSplitRule(r.Kind, r.Value, r.Label)
		if err != nil {
			return p, err
		}
		n.Enabled = r.Enabled
		out = append(out, n)
	}
	p.Rules = out
	return p, nil
}

// ---- runtime matcher -------------------------------------------------------

var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

type compiledSplit struct {
	mode         string
	domains      []string
	prefixes     []netip.Prefix
	lanBypass    bool
	excludedDNS  string
	protectedIPs map[netip.Addr]bool
	endpoints    []netip.Addr
}

// compileSplit resolves the persisted policy for a route. CIDRs that would
// capture the tunnel endpoint are dropped: excluding your own exit would only
// create a loop or leak.
func compileSplit(policy SplitPolicy, endpointIPs []string) *compiledSplit {
	c := &compiledSplit{
		mode:         policy.Mode,
		lanBypass:    policy.LANBypass,
		excludedDNS:  policy.ExcludedDNS,
		protectedIPs: map[netip.Addr]bool{},
	}
	if c.mode == "" {
		c.mode = "off"
	}
	if c.excludedDNS == "" {
		c.excludedDNS = "tunnel"
	}
	for _, ip := range endpointIPs {
		if a, err := netip.ParseAddr(ip); err == nil {
			c.endpoints = append(c.endpoints, a)
			c.protectedIPs[a] = true
		}
	}
	for _, r := range policy.Rules {
		if !ruleEnabled(r) {
			continue
		}
		switch r.Kind {
		case "domain":
			c.domains = append(c.domains, r.Value)
		case "cidr":
			prefix, err := netip.ParsePrefix(r.Value)
			if err != nil || prefix.Bits() == 0 {
				continue
			}
			skip := false
			for _, ep := range c.endpoints {
				if prefix.Contains(ep) {
					skip = true
					break
				}
			}
			if !skip {
				c.prefixes = append(c.prefixes, prefix)
			}
		}
	}
	return c
}

func (c *compiledSplit) domainMatches(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return false
	}
	for _, d := range c.domains {
		if strings.HasPrefix(d, "*.") {
			suffix := strings.TrimPrefix(d, "*.")
			if strings.HasSuffix(h, "."+suffix) {
				return true
			}
		} else if h == d {
			return true
		}
	}
	return false
}

func (c *compiledSplit) prefixMatches(ip netip.Addr) bool {
	for _, p := range c.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *compiledSplit) isLAN(ip netip.Addr) bool {
	if c.protectedIPs[ip] {
		return false
	}
	for _, p := range lanPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// direct decides whether a destination bypasses the tunnel. host may be empty
// when the caller only has an IP; ip may be invalid when it has not resolved yet.
func (c *compiledSplit) direct(host string, ip netip.Addr) bool {
	hasIP := ip.IsValid()
	switch c.mode {
	case "include":
		if c.domainMatches(host) {
			return false
		}
		if hasIP && c.prefixMatches(ip) {
			return false
		}
		if c.lanBypass && hasIP && c.isLAN(ip) {
			return true
		}
		return true
	case "exclude":
		if c.domainMatches(host) {
			return true
		}
		if hasIP && c.prefixMatches(ip) {
			return true
		}
		if c.lanBypass && hasIP && c.isLAN(ip) {
			return true
		}
		return false
	default:
		return c.lanBypass && hasIP && c.isLAN(ip)
	}
}

// hasActiveRules reports whether split tunneling can ever bypass the tunnel.
func (c *compiledSplit) hasActiveRules() bool {
	if c.mode == "off" && !c.lanBypass {
		return false
	}
	return len(c.domains) > 0 || len(c.prefixes) > 0 || c.lanBypass
}

func splitPolicyJSON(p SplitPolicy) string {
	b, _ := json.MarshalIndent(p, "", "  ")
	return string(b)
}
