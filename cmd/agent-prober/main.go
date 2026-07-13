// Command agent-prober is the optional AIM-archetype real-signal producer (design
// §6.6): it keeps each agent's sealed baselines from the simulated TL events but
// derives the live observed side from real DNS queries and TLS handshakes, then
// POSTs the resulting observations to agent-trust-discovery. The projection/HTTP logic lives
// in internal/prober; this binary supplies the real network probe. It is not part
// of `make demo`.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/prober"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "config/prober.yaml", "path to the prober config YAML")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	s, err := prober.LoadConfig(*configPath)
	if err != nil {
		logger.ErrorContext(ctx, "prober: load config", "error", err, "path", *configPath)
		return 1
	}
	events, err := tlevent.LoadDir(s.TLEventsDir)
	if err != nil {
		logger.ErrorContext(ctx, "prober: load tl-events", "error", err)
		return 1
	}

	p := prober.New(prober.Config{
		BaseURL:  s.TargetURL,
		AdminKey: s.AdminKey,
		AIMID:    s.AIMID,
		Now:      func() string { return time.Now().UTC().Format(time.RFC3339) },
		Logger:   logger,
	}, netProbe{timeout: s.Timeout}, &http.Client{Timeout: s.Timeout + 5*time.Second})

	pass := func() error {
		summary, err := p.RunOnce(ctx, events)
		if err != nil {
			logger.ErrorContext(ctx, "prober: pass failed", "error", err)
			return err
		}
		logger.InfoContext(ctx, "prober: pass complete", "observationsEmitted", summary.ObservationsEmitted)
		return nil
	}

	// Single-pass exit code must reflect the pass result — a failed probe run
	// (e.g. agent-trust-discovery rejects the import) that exited 0 would look like a
	// clean run to run-demo-live.sh (set -e) and to CI.
	if err := pass(); err != nil && s.Cadence <= 0 {
		return 1
	}
	if s.Cadence <= 0 {
		return 0
	}
	ticker := time.NewTicker(s.Cadence)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			_ = pass()
		}
	}
}

// netProbe is the real implementation of prober.Probe. CAA and DNSSEC are not
// validated in v1 (the standard library has no CAA/DNSSEC-aware resolver); it
// reports caa=false, and certtype is a Subject-Organization heuristic (OV when
// present, else DV; EV detection via policy OIDs is deferred).
type netProbe struct{ timeout time.Duration }

func (np netProbe) Cert(ctx context.Context, host string) (prober.CertResult, error) {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: np.timeout,
			// SSRF guard: host comes from a prod TL response, so a hostile
			// registration could point us at cloud metadata (169.254.169.254),
			// RFC1918, loopback, etc. Control runs after DNS resolution but
			// before the connect, so it also closes DNS-rebinding.
			Control: blockInternalAddr,
		},
		// Inspecting the served certificate, not establishing a trusted channel.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec // probe inspects the cert; trust is not asserted
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return prober.CertResult{}, err
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return prober.CertResult{}, errors.New("not a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return prober.CertResult{}, errors.New("no peer certificate")
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	// certType is a heuristic, not an authoritative validation-tier read.
	// Presence of a Subject Organization is treated as OV, its absence as DV;
	// EV detection is deferred entirely (v1). This over-reports OV: many DV /
	// automated-issuance certs still carry an Organization, so a DV cert can
	// be scored as OV. A precise read would parse the certificate-policy OIDs
	// (e.g. the CA/B Forum DV/OV/EV policy identifiers) rather than infer from
	// the subject. Until then, downstream trust scoring should treat this
	// field as best-effort. (v2: policy-OID parsing.)
	certType := "DV"
	if len(leaf.Subject.Organization) > 0 {
		certType = "OV"
	}
	return prober.CertResult{Fingerprint: "SHA256:" + hex.EncodeToString(sum[:]), Type: certType}, nil
}

func (np netProbe) TXT(ctx context.Context, name string) (string, error) {
	// Cap the DNS lookup with the same timeout the TLS dialer uses; the
	// stdlib resolver relies entirely on context for deadlines, and a
	// slow/black-holing nameserver would otherwise hang the sequential pass.
	ctx, cancel := context.WithTimeout(ctx, np.timeout)
	defer cancel()
	recs, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return "", errors.New("no TXT record")
	}
	return strings.TrimSpace(recs[0]), nil
}

func (np netProbe) CAA(context.Context, string) (bool, error) {
	// Deferred: the standard library has no CAA lookup. v1 reports no CAA.
	return false, nil
}

// blockInternalAddr is a net.Dialer.Control hook that refuses to open a
// connection to an internal / link-local / loopback / unspecified address.
// The prober's `host` comes from a prod TL response — a hostile registration
// could point us at cloud metadata (169.254.169.254), RFC1918, loopback, etc.
// Control runs after DNS resolution but before the connect syscall, so a
// name that resolves to an internal IP between our own resolution and the
// kernel's (DNS rebinding) is caught here too. address is always host:port
// with host as the resolved IP literal.
func blockInternalAddr(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("prober: parse dial target %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("prober: refusing non-IP dial target %q", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("prober: refusing to dial internal address %s", ip)
	}
	return nil
}
