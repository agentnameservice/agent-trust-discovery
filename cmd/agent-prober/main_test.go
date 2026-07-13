package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// blockInternalAddr closes an SSRF hole: the prober's `host` comes from a
// prod TL response, so a hostile registration could aim the live TLS dial
// at cloud metadata / RFC1918 / loopback. The Control hook runs after DNS
// resolution with the resolved IP:port, so this covers the DNS-rebinding
// path as well as a literal-IP hostname.
func TestBlockInternalAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"loopback v4", "127.0.0.1:443", true},
		{"loopback v6", "[::1]:443", true},
		{"unspecified v4", "0.0.0.0:443", true},
		{"unspecified v6", "[::]:443", true},
		{"RFC1918 10/8", "10.0.0.5:443", true},
		{"RFC1918 172.16/12", "172.16.5.5:443", true},
		{"RFC1918 192.168/16", "192.168.1.1:443", true},
		{"link-local unicast v4 (cloud metadata)", "169.254.169.254:443", true},
		{"link-local unicast v6", "[fe80::1]:443", true},
		{"link-local multicast v4", "224.0.0.1:443", true},
		{"link-local multicast v6", "[ff02::1]:443", true},
		{"IPv6 unique-local fc00::/7", "[fd00::1]:443", true},
		{"non-IP host slips through", "not-an-ip:443", true},
		{"malformed address", "not-a-host-port", true},
		{"public v4 allowed", "8.8.8.8:443", false},
		{"public v6 allowed", "[2001:4860:4860::8888]:443", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := blockInternalAddr("tcp", tc.addr, nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("blockInternalAddr(%q) err=%v, wantErr=%v", tc.addr, err, tc.wantErr)
			}
		})
	}
}

// TestNetProbe_Cert_RefusesInternal proves the SSRF guard is actually wired
// into netProbe.Cert's dialer — a regression here (someone drops the Control
// hook) would let the prober open TLS to internal targets again. Uses a
// literal-IP host so we don't depend on DNS behaviour; short timeout keeps
// the test fast if the guard is ever bypassed.
func TestNetProbe_Cert_RefusesInternal(t *testing.T) {
	np := netProbe{timeout: 100 * time.Millisecond}
	_, err := np.Cert(context.Background(), "127.0.0.1")
	if err == nil {
		t.Fatal("Cert(127.0.0.1) returned nil error; SSRF guard is not wired in")
	}
	if !strings.Contains(err.Error(), "refusing to dial internal address") {
		t.Errorf("Cert(127.0.0.1) err=%v, want SSRF-guard message", err)
	}
}
