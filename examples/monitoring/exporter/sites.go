package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// Site is what an IP maps to in the sites file: the location it belongs to
// and a class such as "internal" or "public".
type Site struct {
	Name  string
	Class string
}

const unknownClass = "other"

// Sites maps IP prefixes to sites. Lookups use the longest matching prefix;
// IPs without a match are their own site with class "other".
type Sites struct {
	entries []siteEntry // longest prefix first
}

type siteEntry struct {
	prefix netip.Prefix
	site   Site
}

// LoadSites reads a sites file. Each non-empty line is
//
//	<ip or prefix> <site> [class]
//
// and '#' starts a comment. An empty path yields an empty mapping.
func LoadSites(path string) (*Sites, error) {
	if path == "" {
		return &Sites{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseSites(f)
}

func ParseSites(r io.Reader) (*Sites, error) {
	s := &Sites{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 || len(f) > 3 {
			return nil, fmt.Errorf("line %d: want \"<prefix> <site> [class]\", got %q", n, sc.Text())
		}
		p, err := parsePrefix(f[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		site := Site{Name: f[1], Class: unknownClass}
		if len(f) == 3 {
			site.Class = f[2]
		}
		s.entries = append(s.entries, siteEntry{p, site})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(s.entries, func(a, b siteEntry) int { return b.prefix.Bits() - a.prefix.Bits() })
	return s, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Lookup returns the site of ip.
func (s *Sites) Lookup(ip string) Site {
	if s != nil {
		if a, err := netip.ParseAddr(ip); err == nil {
			a = a.Unmap()
			for _, e := range s.entries {
				if e.prefix.Contains(a) {
					return e.site
				}
			}
		}
	}
	return Site{Name: ip, Class: unknownClass}
}

func (s *Sites) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}
