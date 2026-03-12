package asn

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func Test_normalizeASN(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "13335", want: "AS13335"},
		{in: "as13335", want: "AS13335"},
		{in: " AS15169 ", want: "AS15169"},
		{in: "", want: ""},
	}

	for _, tt := range tests {
		if got := normalizeASN(tt.in); got != tt.want {
			t.Errorf("normalizeASN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func Test_parseCymruASN(t *testing.T) {
	resp := `AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
13335   | 1.1.1.1          | 1.1.1.0/24          | AU | apnic    | 2011-08-11 | CLOUDFLARENET`

	asn, ok := parseCymruASN(resp)
	if !ok || asn != "AS13335" {
		t.Fatalf("parseCymruASN() = (%q, %v), want (AS13335, true)", asn, ok)
	}
}

func Test_parseCymruDNSTXT(t *testing.T) {
	records := []string{"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"}

	asn, ok := parseCymruDNSTXT(records)
	if !ok || asn != "AS13335" {
		t.Fatalf("parseCymruDNSTXT() = (%q, %v), want (AS13335, true)", asn, ok)
	}
}

func Test_dnsQueryName(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "ipv4", ip: "216.90.108.31", want: "31.108.90.216.origin.asn.cymru.com"},
		{name: "ipv6", ip: "2001:4860:b002::68", want: "8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.b.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsQueryName(tt.ip)
			if err != nil {
				t.Fatalf("dnsQueryName(%q) error = %v", tt.ip, err)
			}
			if got != tt.want {
				t.Fatalf("dnsQueryName(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func Test_parseWhoisRefer(t *testing.T) {
	resp := "organisation: ARIN\nrefer: whois.arin.net\n"
	if got := parseWhoisRefer(resp); got != "whois.arin.net" {
		t.Fatalf("parseWhoisRefer() = %q, want whois.arin.net", got)
	}
}

func Test_parseRIRASN(t *testing.T) {
	tests := []struct {
		name string
		resp string
		want string
	}{
		{name: "origin", resp: "origin: AS64500", want: "AS64500"},
		{name: "originas", resp: "originas: 64501", want: "AS64501"},
		{name: "aut-num", resp: "aut-num: AS64496", want: "AS64496"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRIRASN(tt.resp)
			if !ok || got != tt.want {
				t.Fatalf("parseRIRASN() = (%q, %v), want (%q, true)", got, ok, tt.want)
			}
		})
	}
}

func Test_lookupRIRFallback(t *testing.T) {
	queryFn := func(server, query string) (string, error) {
		switch server {
		case "whois.iana.org:43":
			return "refer: whois.arin.net\n", nil
		case "whois.arin.net:43":
			return "originas: AS3356\n", nil
		default:
			return "", errors.New("unexpected server")
		}
	}

	asn, ok := lookupRIRFallback("4.2.2.2", queryFn)
	if !ok || asn != "AS3356" {
		t.Fatalf("lookupRIRFallback() = (%q, %v), want (AS3356, true)", asn, ok)
	}
}

func Test_lookupDNSASN_RetriesBeforeMiss(t *testing.T) {
	var calls atomic.Int32
	lookupTXT := func(name string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("temporary dns failure")
	}

	if asn, ok := lookupDNSASN("1.1.1.1", lookupTXT, 2, 0); ok || asn != "" {
		t.Fatalf("lookupDNSASN() = (%q, %v), want (empty, false)", asn, ok)
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf("dns lookups = %d, want 2", got)
	}
}

func Test_lookupASNWithResolvers_DNSBeforeWhoisFallback(t *testing.T) {
	var dnsCalls atomic.Int32
	var whoisCalls atomic.Int32

	lookupTXT := func(name string) ([]string, error) {
		dnsCalls.Add(1)
		return nil, errors.New("temporary dns failure")
	}
	queryWhois := func(server, query string) (string, error) {
		whoisCalls.Add(1)
		if server == "whois.cymru.com:43" {
			return "13335 | 1.1.1.1 | 1.1.1.0/24 | AU | apnic | 2011-08-11\n", nil
		}
		return "", errors.New("unexpected server")
	}

	asn, err := lookupASNWithResolvers("1.1.1.1", lookupTXT, 2, 0, queryWhois)
	if err != nil {
		t.Fatalf("lookupASNWithResolvers() error = %v", err)
	}
	if asn != "AS13335" {
		t.Fatalf("lookupASNWithResolvers() = %q, want AS13335", asn)
	}
	if got := dnsCalls.Load(); got != 2 {
		t.Fatalf("dns lookups = %d, want 2", got)
	}
	if got := whoisCalls.Load(); got != 1 {
		t.Fatalf("whois lookups = %d, want 1", got)
	}
}

func Test_isPublicRoutableIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public ipv4", ip: "8.8.8.8", want: true},
		{name: "public ipv6", ip: "2606:4700:4700::1111", want: true},
		{name: "rfc1918 private", ip: "10.1.2.3", want: false},
		{name: "ipv6 ula private", ip: "fd00::1", want: false},
		{name: "loopback", ip: "127.0.0.1", want: false},
		{name: "link local", ip: "169.254.1.1", want: false},
		{name: "cgnat", ip: "100.64.0.1", want: false},
		{name: "test-net", ip: "192.0.2.1", want: false},
		{name: "ipv6 docs", ip: "2001:db8::1", want: false},
		{name: "invalid", ip: "not-an-ip", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPublicRoutableIP(tt.ip); got != tt.want {
				t.Fatalf("isPublicRoutableIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestASNManager_RequestASN(t *testing.T) {
	t.Run("successful lookup and cache", func(t *testing.T) {
		am := &ASNManager{
			cache: make(map[string]string),
			lookupFunc: func(ip string) (string, error) {
				return "13335", nil
			},
			retries:    1,
			retryDelay: 0,
		}

		am.RequestASN("1.1.1.1")

		if asn, found := am.GetASN("1.1.1.1"); !found || asn != "AS13335" {
			t.Fatalf("GetASN() = (%q, %v), want (AS13335, true)", asn, found)
		}
	})

	t.Run("already cached skips lookup", func(t *testing.T) {
		am := &ASNManager{
			cache: map[string]string{"1.1.1.1": "AS13335"},
			lookupFunc: func(ip string) (string, error) {
				t.Fatal("lookupFunc should not be called for cached IP")
				return "", nil
			},
			retries:    1,
			retryDelay: 0,
		}

		am.RequestASN("1.1.1.1")
		if asn, _ := am.GetASN("1.1.1.1"); asn != "AS13335" {
			t.Fatalf("GetASN() = %q, want AS13335", asn)
		}
	})

	t.Run("failed lookup marks in progress", func(t *testing.T) {
		am := &ASNManager{
			cache: make(map[string]string),
			lookupFunc: func(ip string) (string, error) {
				return "", errors.New("failed")
			},
			retries:    1,
			retryDelay: 0,
		}

		am.RequestASN("1.1.1.1")
		if asn, found := am.GetASN("1.1.1.1"); found || asn != "" {
			t.Fatalf("GetASN() = (%q, %v), want (empty, false)", asn, found)
		}
	})

	t.Run("non-public ip skips lookup", func(t *testing.T) {
		am := &ASNManager{
			cache: make(map[string]string),
			lookupFunc: func(ip string) (string, error) {
				t.Fatal("lookupFunc should not be called for non-public IP")
				return "", nil
			},
			retries:    2,
			retryDelay: 0,
		}

		am.RequestASN("10.0.0.1")
		if asn, found := am.GetASN("10.0.0.1"); found || asn != "" {
			t.Fatalf("GetASN() = (%q, %v), want (empty, false)", asn, found)
		}
	})
}

func TestASNManager_Concurrency(t *testing.T) {
	am := &ASNManager{
		cache: make(map[string]string),
		lookupFunc: func(ip string) (string, error) {
			time.Sleep(time.Millisecond)
			return "AS" + ip[len(ip)-1:], nil
		},
		retries:    1,
		retryDelay: 0,
	}

	ips := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, ip := range ips {
				am.RequestASN(ip)
				am.GetASN(ip)
			}
		}()
	}
	wg.Wait()

	for _, ip := range ips {
		if _, found := am.GetASN(ip); !found {
			t.Fatalf("expected cached ASN for %s", ip)
		}
	}
}

func TestASNManager_RequestASN_ConcurrentDedupSameIP(t *testing.T) {
	var calls atomic.Int32
	am := &ASNManager{
		cache: make(map[string]string),
		lookupFunc: func(ip string) (string, error) {
			calls.Add(1)
			time.Sleep(5 * time.Millisecond)
			return "13335", nil
		},
		retries:    1,
		retryDelay: 0,
	}

	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.RequestASN("1.1.1.1")
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("lookupFunc calls = %d, want 1", got)
	}

	if asn, found := am.GetASN("1.1.1.1"); !found || asn != "AS13335" {
		t.Fatalf("GetASN() = (%q, %v), want (AS13335, true)", asn, found)
	}
}
