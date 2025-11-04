package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	var (
		sourcePort = flag.Int("p", 0, "Source port to bind to")
		timeout    = flag.Duration("t", 30*time.Second, "Request timeout")
		verbose    = flag.Bool("v", false, "Verbose output")
		forceIPv4  = flag.Bool("4", false, "Force IPv4")
		forceIPv6  = flag.Bool("6", false, "Force IPv6")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <URL>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Make HTTP requests from a specific source port.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -p 33434 -v https://example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p 33434 -4 https://example.com  # Force IPv4\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p 33434 -6 https://example.com  # Force IPv6\n", os.Args[0])
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	url := flag.Arg(0)

	if *sourcePort < 1 || *sourcePort > 65535 {
		fmt.Fprintf(os.Stderr, "Error: Source port must be between 1 and 65535\n")
		os.Exit(1)
	}

	if *forceIPv4 && *forceIPv6 {
		fmt.Fprintf(os.Stderr, "Error: Cannot specify both -4 and -6\n")
		os.Exit(1)
	}

	// Determine network type
	network := "tcp"
	if *forceIPv4 {
		network = "tcp4"
	} else if *forceIPv6 {
		network = "tcp6"
	}

	if *verbose {
		fmt.Printf("Making request to %s from source port %d (%s)\n", url, *sourcePort, network)
	}

	// Create a custom dialer that binds to the specified source port
	dialer := &net.Dialer{
		Timeout: *timeout,
		LocalAddr: &net.TCPAddr{
			Port: *sourcePort,
		},
	}

	// Create HTTP client with custom transport
	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing response body: %v\n", err)
		}
	}()

	duration := time.Since(start)

	if *verbose {
		// Get local address info
		if tcpConn, ok := resp.Request.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
			fmt.Printf("Connected from %s\n", tcpConn.String())
		}
		fmt.Printf("Response time: %v\n", duration)
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Content-Length: %d\n", resp.ContentLength)
		fmt.Println("Headers:")
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Copy response body to stdout
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("\nRequest completed in %v\n", duration)
	}
}
