package asn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LookupFunc is a function type for ASN lookups.
type LookupFunc func(ip string) (string, error)

// ASNManager handles ASN lookups with simple caching.
// Empty cache entries represent in-progress or unresolved lookups.
type ASNManager struct {
	cache      map[string]string
	mu         sync.RWMutex
	lookupFunc LookupFunc
	retries    int
	retryDelay time.Duration
}

// NewASNManager creates a new ASNManager with default settings.
func NewASNManager() *ASNManager {
	return &ASNManager{
		cache:      make(map[string]string),
		lookupFunc: lookupASN,
		retries:    2,
		retryDelay: 100 * time.Millisecond,
	}
}

func normalizeASN(asn string) string {
	trimmed := strings.TrimSpace(strings.ToUpper(asn))
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "AS") {
		return trimmed
	}
	return "AS" + trimmed
}

func (am *ASNManager) markInProgressIfNeeded(ip string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.cache[ip]; exists {
		return false
	}

	am.cache[ip] = ""
	return true
}

func (am *ASNManager) setCached(ip, asn string) {
	am.mu.Lock()
	am.cache[ip] = asn
	am.mu.Unlock()
}

func (am *ASNManager) performLookup(ip string) (string, bool) {
	if !isPublicRoutableIP(ip) {
		return "", false
	}

	for range am.retries {
		asn, err := am.lookupFunc(ip)
		if err == nil && asn != "" {
			return normalizeASN(asn), true
		}
		if am.retryDelay > 0 {
			time.Sleep(am.retryDelay)
		}
	}
	return "", false
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // Carrier-grade NAT
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmark testing
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved for future use
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("2001:db8::/32"), // Documentation
}

func isPublicRoutableIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	if addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsPrivate() {
		return false
	}

	for _, pfx := range nonPublicPrefixes {
		if pfx.Contains(addr) {
			return false
		}
	}

	return true
}

// RequestASN initiates an ASN lookup for the given IP if not cached.
func (am *ASNManager) RequestASN(ip string) {
	if !am.markInProgressIfNeeded(ip) {
		return
	}

	if asn, ok := am.performLookup(ip); ok {
		am.setCached(ip, asn)
	}
}

// GetASN retrieves a cached ASN for the given IP address.
// Returns the ASN and a boolean indicating if a non-empty value exists.
func (am *ASNManager) GetASN(ip string) (string, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	asn, exists := am.cache[ip]
	if asn == "" {
		return "", false
	}
	return asn, exists
}

type whoisQueryFunc func(server, query string) (string, error)
type dnsTXTLookupFunc func(name string) ([]string, error)

const (
	defaultDNSRetries    = 2
	defaultDNSRetryDelay = 100 * time.Millisecond
)

func lookupASN(ip string) (string, error) {
	return lookupASNWithResolvers(ip, lookupTXTRecords, defaultDNSRetries, defaultDNSRetryDelay, queryWhoisServer)
}

// lookupASNWithResolvers tries DNS-based ASN resolution first, then falls back to WHOIS-based lookups.
func lookupASNWithResolvers(ip string, lookupTXT dnsTXTLookupFunc, dnsRetries int, dnsRetryDelay time.Duration, queryWhois whoisQueryFunc) (string, error) {
	// DNS is preferred due to lightness and caching
	if asn, ok := lookupDNSASN(ip, lookupTXT, dnsRetries, dnsRetryDelay); ok {
		return asn, nil
	}

	if asn, ok := lookupTeamCymru(ip, queryWhois); ok {
		return asn, nil
	}
	if asn, ok := lookupRIRFallback(ip, queryWhois); ok {
		return asn, nil
	}
	return "", fmt.Errorf("asn lookup failed for ip %s", ip)
}

func lookupDNSASN(ip string, lookupTXT dnsTXTLookupFunc, retries int, retryDelay time.Duration) (string, bool) {
	queryName, err := dnsQueryName(ip)
	if err != nil {
		return "", false
	}

	for attempt := 0; attempt < retries; attempt++ {
		records, err := lookupTXT(queryName)
		if err == nil {
			if asn, ok := parseCymruDNSTXT(records); ok {
				return asn, true
			}
		}

		if attempt+1 < retries && retryDelay > 0 {
			time.Sleep(retryDelay)
		}
	}

	return "", false
}

func lookupTXTRecords(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return net.DefaultResolver.LookupTXT(ctx, name)
}

// dnsQueryName builds the Team Cymru reverse-DNS query name for IPv4 and IPv6 addresses.
func dnsQueryName(ip string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", err
	}
	addr = addr.Unmap()

	if addr.Is4() {
		bytes := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", bytes[3], bytes[2], bytes[1], bytes[0]), nil
	}

	if addr.Is6() {
		bytes := addr.As16()
		parts := make([]string, 0, len(bytes)*2)
		for idx := len(bytes) - 1; idx >= 0; idx-- {
			parts = append(parts,
				strconv.FormatUint(uint64(bytes[idx]&0x0f), 16),
				strconv.FormatUint(uint64(bytes[idx]>>4), 16),
			)
		}
		return strings.Join(parts, ".") + ".origin6.asn.cymru.com", nil
	}

	return "", fmt.Errorf("unsupported ip address %q", ip)
}

func parseCymruDNSTXT(records []string) (string, bool) {
	for _, record := range records {
		parts := strings.Split(record, "|")
		if len(parts) == 0 {
			continue
		}

		asn := strings.TrimSpace(parts[0])
		if asn == "" || strings.EqualFold(asn, "NA") {
			continue
		}
		if strings.IndexFunc(asn, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
			continue
		}

		return normalizeASN(asn), true
	}

	return "", false
}

func lookupTeamCymru(ip string, queryFn whoisQueryFunc) (string, bool) {
	resp, err := queryFn("whois.cymru.com:43", fmt.Sprintf(" -v %s\n", ip))
	if err != nil {
		return "", false
	}
	if asn, ok := parseCymruASN(resp); ok {
		return asn, true
	}
	return "", false
}

func lookupRIRFallback(ip string, queryFn whoisQueryFunc) (string, bool) {
	referral := ""
	if resp, err := queryFn("whois.iana.org:43", ip+"\n"); err == nil {
		referral = parseWhoisRefer(resp)
	}

	servers := make([]string, 0, 6)
	if referral != "" {
		if !strings.Contains(referral, ":") {
			referral += ":43"
		}
		servers = append(servers, referral)
	}
	servers = append(servers,
		"whois.arin.net:43",
		"whois.ripe.net:43",
		"whois.apnic.net:43",
		"whois.lacnic.net:43",
		"whois.afrinic.net:43",
	)

	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if _, exists := seen[server]; exists {
			continue
		}
		seen[server] = struct{}{}

		resp, err := queryFn(server, ip+"\n")
		if err != nil {
			continue
		}
		if asn, ok := parseRIRASN(resp); ok {
			return asn, true
		}
	}

	return "", false
}

func queryWhoisServer(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte(query)); err != nil {
		return "", err
	}

	var builder strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		builder.WriteString(scanner.Text())
		builder.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return builder.String(), nil
}

func parseCymruASN(resp string) (string, bool) {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) == 0 {
			continue
		}

		asn := strings.TrimSpace(parts[0])
		if asn == "" || strings.EqualFold(asn, "NA") {
			continue
		}
		if strings.IndexFunc(asn, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
			continue
		}

		return normalizeASN(asn), true
	}

	return "", false
}

func parseWhoisRefer(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if (key == "refer" || key == "whois") && value != "" {
			return value
		}
	}

	return ""
}

var rirASNRegex = regexp.MustCompile(`(?i)\b(?:originas|origin|aut-num)\s*:\s*((?:AS)?\d+)`)

func parseRIRASN(resp string) (string, bool) {
	match := rirASNRegex.FindStringSubmatch(resp)
	if len(match) < 2 {
		return "", false
	}

	return normalizeASN(match[1]), true
}
