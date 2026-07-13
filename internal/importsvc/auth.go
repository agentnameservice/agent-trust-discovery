package importsvc

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// AdminAuthConfig configures the bearer-key gate on the /v1/internal/* import
// routes (design §5.3). It maps directly to the runtime.yaml `admin` block.
type AdminAuthConfig struct {
	RequireKey bool   // when true, a matching Authorization: Bearer <Key> is mandatory
	Key        string // the static admin key
}

// UnauthenticatedWarning is logged at WARN once at boot (by the caller) when
// the routes run without auth (design §5.3). It is deliberately NOT re-logged
// per request: the boot warning plus the audit line's authenticated:false
// field already make the unauthenticated posture visible, and a per-call WARN
// was just noise on every admin request.
const UnauthenticatedWarning = "admin import routes are unauthenticated; do not expose this binary to untrusted networks"

// NewAdminAuth builds the admin-key middleware. It fails fast — returning an
// error the caller must treat as a boot failure — when RequireKey is true but
// Key is empty (§5.3: secure-by-default config must not silently disable auth).
//
// When RequireKey is true the middleware requires "Authorization: Bearer <Key>"
// (compared in constant time) and answers 401 RFC 7807 otherwise. When
// RequireKey is false every request passes through; the unauthenticated
// posture is surfaced by the boot-time UnauthenticatedWarning and the audit
// line's authenticated:false field rather than a per-request log line.
//
// The logger parameter is retained (nil → slog.Default()) for call-site
// compatibility and future per-request diagnostics, even though the middleware
// no longer logs on the hot path.
func NewAdminAuth(cfg AdminAuthConfig, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	if cfg.RequireKey && cfg.Key == "" {
		return nil, errors.New("importsvc: admin.requireKey is true but admin.key is empty")
	}
	_ = logger // retained for call-site compatibility; no longer logs per request (see doc)
	expected := []byte("Bearer " + cfg.Key)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.RequireKey {
				next.ServeHTTP(w, r)
				return
			}
			got := []byte(r.Header.Get("Authorization"))
			if subtle.ConstantTimeCompare(got, expected) != 1 {
				web.WriteProblem(w, web.NewError(http.StatusUnauthorized, CodeUnauthorized,
					"missing or invalid admin bearer key"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
