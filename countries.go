package main

import (
	"context"
	"sort"
	"strings"
)

var countryNames = map[string]string{
	"US": "United States", "CA": "Canada", "DE": "Germany", "NL": "Netherlands",
	"FR": "France", "GB": "United Kingdom", "CZ": "Czechia", "PL": "Poland",
	"SG": "Singapore", "JP": "Japan", "AU": "Australia", "BR": "Brazil",
	"ES": "Spain", "IT": "Italy", "SE": "Sweden", "CH": "Switzerland",
	"AT": "Austria", "FI": "Finland", "MX": "Mexico", "KR": "South Korea",
	"IN": "India", "ZA": "South Africa", "RU": "Russia", "MY": "Malaysia",
	"HK": "Hong Kong", "AE": "United Arab Emirates",
}

var countryCities = map[string]string{
	"US": "Multiple cities", "CA": "Toronto", "DE": "Frankfurt", "NL": "Amsterdam",
	"FR": "Paris", "GB": "London", "CZ": "Prague", "PL": "Warsaw",
	"SG": "Singapore", "JP": "Tokyo", "AU": "Sydney", "BR": "São Paulo",
	"ES": "Madrid", "IT": "Milan", "SE": "Stockholm", "CH": "Zürich",
	"AT": "Vienna", "FI": "Helsinki", "MX": "Mexico City", "KR": "Seoul",
	"IN": "Mumbai", "ZA": "Johannesburg", "RU": "Moscow", "MY": "Kuala Lumpur",
	"HK": "Hong Kong", "AE": "Dubai",
}

// Country is one picker row: a country (GroupByCountry) or a city
// (GroupByLocation).
type Country struct {
	ID        string
	Code      string
	Flag      string
	Name      string
	City      string
	NodeCount int
	Best      GatewayInfo
	IPs       []string
	LatencyMs *int64
}

func localityOf(cityFromGateway, code string) string {
	if c := strings.TrimSpace(cityFromGateway); c != "" {
		return c
	}
	return countryCities[code]
}

func countryName(code string) string {
	if n, ok := countryNames[code]; ok {
		return n
	}
	return code
}

func flagEmoji(code string) string {
	cc := strings.ToUpper(strings.TrimSpace(code))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "🏳️"
	}
	return string(rune(0x1F1E6+int(cc[0]-'A'))) + string(rune(0x1F1E6+int(cc[1]-'A')))
}

func latencyBand(ms *int64) string {
	if ms == nil || *ms >= 180 {
		return "slow"
	}
	if *ms < 60 {
		return "good"
	}
	return "ok"
}

func bestOf(list []GatewayInfo, latency map[string]int64) GatewayInfo {
	measured := make([]GatewayInfo, 0, len(list))
	for _, gw := range list {
		if _, ok := latency[gw.IP]; ok {
			measured = append(measured, gw)
		}
	}
	pool := list
	if len(measured) > 0 {
		pool = measured
	}
	best := pool[0]
	bestScore := -1
	for _, gw := range pool {
		var ms *int64
		if v, ok := latency[gw.IP]; ok {
			ms = &v
		}
		score := gatewayQuality(ms, gw.Load).Score
		if score > bestScore {
			best = gw
			bestScore = score
		}
	}
	return best
}

func groupByCountry(gateways []GatewayInfo, latency map[string]int64) []Country {
	byCode := make(map[string][]GatewayInfo)
	for _, gw := range gateways {
		byCode[gw.Country] = append(byCode[gw.Country], gw)
	}
	rows := make([]Country, 0, len(byCode))
	for code, list := range byCode {
		best := bestOf(list, latency)
		ips := make([]string, 0, len(list))
		for _, gw := range list {
			ips = append(ips, gw.IP)
		}
		var ms *int64
		if v, ok := latency[best.IP]; ok {
			ms = &v
		}
		rows = append(rows, Country{
			ID: code, Code: code, Flag: flagEmoji(code), Name: countryName(code),
			City: localityOf(best.City, code), NodeCount: len(list), Best: best,
			IPs: ips, LatencyMs: ms,
		})
	}
	sortByNearest(rows)
	return rows
}

func groupByLocation(gateways []GatewayInfo, latency map[string]int64) []Country {
	byLoc := make(map[string][]GatewayInfo)
	for _, gw := range gateways {
		city := localityOf(gw.City, gw.Country)
		key := gw.Country
		if city != "" {
			key = gw.Country + ":" + city
		}
		byLoc[key] = append(byLoc[key], gw)
	}
	rows := make([]Country, 0, len(byLoc))
	for id, list := range byLoc {
		best := bestOf(list, latency)
		code := best.Country
		ips := make([]string, 0, len(list))
		for _, gw := range list {
			ips = append(ips, gw.IP)
		}
		var ms *int64
		if v, ok := latency[best.IP]; ok {
			ms = &v
		}
		rows = append(rows, Country{
			ID: id, Code: code, Flag: flagEmoji(code), Name: countryName(code),
			City: localityOf(best.City, code), NodeCount: len(list), Best: best,
			IPs: ips, LatencyMs: ms,
		})
	}
	sortByNearest(rows)
	return rows
}

func sortByNearest(rows []Country) {
	sort.SliceStable(rows, func(i, j int) bool {
		li, lj := int64(1<<62), int64(1<<62)
		if rows[i].LatencyMs != nil {
			li = *rows[i].LatencyMs
		}
		if rows[j].LatencyMs != nil {
			lj = *rows[j].LatencyMs
		}
		if li != lj {
			return li < lj
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].City < rows[j].City
	})
}

// measureFleetLatencies pings each distinct row "best" once, in parallel.
func measureFleetLatencies(gateways []GatewayInfo, countries, locations []Country) map[string]int64 {
	bests := make(map[string]GatewayInfo)
	for _, c := range countries {
		bests[c.Best.IP] = c.Best
	}
	for _, l := range locations {
		bests[l.Best.IP] = l.Best
	}
	type result struct {
		ip string
		ms *int64
	}
	ch := make(chan result, len(bests))
	for ip, gw := range bests {
		go func(ip string, gw GatewayInfo) {
			ch <- result{ip: ip, ms: measureLatency(context.Background(), gw)}
		}(ip, gw)
	}
	out := make(map[string]int64)
	for range bests {
		r := <-ch
		if r.ms != nil {
			out[r.ip] = *r.ms
		}
	}
	return out
}

// routeEndpoint is one resolved hop of the live route.
type RouteEndpoint struct {
	Code       string `json:"code"`
	Flag       string `json:"flag"`
	Name       string `json:"name"`
	City       string `json:"city"`
	IP         string `json:"ip"`
	ControlURL string `json:"controlUrl"`
}

func routeEndpoint(gw GatewayInfo) RouteEndpoint {
	return RouteEndpoint{
		Code: gw.Country, Flag: flagEmoji(gw.Country), Name: countryName(gw.Country),
		City: localityOf(gw.City, gw.Country), IP: gw.IP, ControlURL: gw.ControlURL,
	}
}
