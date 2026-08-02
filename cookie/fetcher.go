package cookie

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// SessionService manages XenForo session cookies as plain strings.
// No http.Client jar is used anywhere — every cookie is stored explicitly
// and overwritten on update, eliminating all accumulation bugs.
type SessionService struct {
	mu       sync.Mutex
	cookies  map[string]string // name → value, last write wins
	domain   *url.URL
	username string
	password string
	tr       *http.Transport  // shared transport, TLS config applied once
	stopCh   chan struct{}
}

// NewSessionService creates a service, performs initial login, and returns.
// scheme is typically "https" but may be "http" for .onion mirrors that
// don't terminate TLS. torSocksProxy, when non-empty (e.g. "127.0.0.1:9050"),
// routes every request this service makes — including the WebSocket dial
// that reuses Transport() — through a Tor SOCKS5 proxy, which is required
// to reach a .onion host. tlsInsecureSkipVerify disables certificate
// verification, which some .onion mirrors need since they serve
// self-signed certs.
func NewSessionService(ctx context.Context, scheme, host, username, password, torSocksProxy string, tlsInsecureSkipVerify bool) (*SessionService, error) {
	u, _ := url.Parse(scheme + "://" + host + "/")

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig()
	if tlsInsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	if torSocksProxy != "" {
		dialer, err := proxy.SOCKS5("tcp", torSocksProxy, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("creating Tor SOCKS5 dialer: %w", err)
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("Tor SOCKS5 dialer does not support DialContext")
		}
		tr.DialContext = contextDialer.DialContext
		log.Printf("🧅 Routing Kiwi Farms connection through Tor SOCKS5 proxy at %s", torSocksProxy)
	}

	s := &SessionService{
		cookies:  make(map[string]string),
		domain:   u,
		username: username,
		password: password,
		tr:       tr,
		stopCh:   make(chan struct{}),
	}

	log.Println("⏳ Logging in to Kiwi Farms...")
	if err := s.Login(ctx); err != nil {
		return nil, fmt.Errorf("initial login: %w", err)
	}
	log.Println("✅ Login successful")

	go s.refreshLoop(ctx)

	return s, nil
}

// Close stops the background refresh loop. Call at shutdown after
// sneedClient.Disconnect().
func (s *SessionService) Close() {
	close(s.stopCh)
}

// refreshLoop proactively renews all session cookies every 4 hours.
// Prevents xf_session and xf_user from expiring mid-run so reconnect
// attempts always have valid credentials. ttrs_clearance is cleared
// so the next WebSocket dial solves it fresh.
func (s *SessionService) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Println("🔄 Proactive session refresh (4h timer)...")
			s.mu.Lock()
			s.deleteCookie("ttrs_clearance")
			if err := s.login(ctx); err != nil {
				log.Printf("⚠️ Proactive session refresh failed: %v", err)
			} else {
				log.Println("✅ Proactive session refresh complete")
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// tlsConfig mirrors sockchat's socketTLSConfig exactly:
// concatenate secure + insecure cipher suites so KiwiFlare TLS fingerprinting
// doesn't trigger. "The insecure ones appear to be necessary for consistently
// getting around 203s." — sockchat source comment.
func tlsConfig() *tls.Config {
	all := slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites())
	ids := make([]uint16, len(all))
	for i, s := range all {
		ids[i] = s.ID
	}
	return &tls.Config{CipherSuites: ids}
}

// Transport returns the shared *http.Transport for use in the WebSocket dialer.
// The caller should use tr.DialContext and tr.TLSClientConfig directly,
// mirroring sockchat's NewSocket pattern.
func (s *SessionService) Transport() *http.Transport {
	return s.tr
}

// setCookie stores a cookie by name, overwriting any previous value.
func (s *SessionService) setCookie(name, value string) {
	s.cookies[name] = value
}

// deleteCookie removes a cookie by name.
func (s *SessionService) deleteCookie(name string) {
	delete(s.cookies, name)
}

// absorbResponse reads all Set-Cookie headers from resp and stores them,
// overwriting any existing values. Each call is idempotent per cookie name.
func (s *SessionService) absorbResponse(resp *http.Response) {
	for _, sc := range resp.Header["Set-Cookie"] {
		seg := strings.SplitN(sc, ";", 2)
		kv := strings.SplitN(strings.TrimSpace(seg[0]), "=", 2)
		if len(kv) == 2 {
			s.cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
}

// cookieHeader returns the current cookie state as a "name=value; ..." string
// suitable for use as a Cookie HTTP header or WebSocket dial header.
func (s *SessionService) cookieHeader() string {
	parts := make([]string, 0, len(s.cookies))
	for k, v := range s.cookies {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// do performs a single HTTP round-trip via the shared transport.
// Injects current cookies, absorbs Set-Cookie from response.
// Does not follow redirects.
func (s *SessionService) do(req *http.Request) (*http.Response, error) {
	if cookie := s.cookieHeader(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := s.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	s.absorbResponse(resp)
	return resp, nil
}

// get performs a GET request, solving any KiwiFlare 203 challenge inline.
// host can differ from s.domain.Host for non-standard port endpoints.
func (s *SessionService) get(ctx context.Context, target *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 203 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("🔑 KiwiFlare 203 on %s — solving PoW...", target.Host)
		if err := s.solveAndSubmit(ctx, body, target.Host); err != nil {
			return nil, fmt.Errorf("PoW solve for %s: %w", target.Host, err)
		}
		return s.get(ctx, target) // retry after solve
	}
	return resp, nil
}

// solveAndSubmit parses a cerberus PoW challenge from the 203 response body,
// solves it, and POSTs the solution to the issuing host (preserving port).
// The resulting ttrs_clearance is absorbed via absorbResponse.
func (s *SessionService) solveAndSubmit(ctx context.Context, body []byte, host string) error {
	salt, diff, err := parseChallengeHTML(string(body))
	if err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}
	log.Printf("🔑 Challenge: salt=%s difficulty=%d", salt, diff)

	nonce, err := solvePoW(ctx, salt, diff)
	if err != nil {
		return err
	}
	log.Printf("✅ Solved: nonce=%d", nonce)

	submitURL := fmt.Sprintf("https://%s/.ttrs/challenge", host)
	body2 := fmt.Sprintf("salt=%s&redirect=/&nonce=%d", url.QueryEscape(salt), nonce)
	req, err := http.NewRequestWithContext(ctx, "POST", submitURL, strings.NewReader(body2))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.do(req)
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	resp.Body.Close()
	log.Printf("✅ Challenge submitted to %s (HTTP %d)", host, resp.StatusCode)
	return nil
}

// Login performs a full XenForo login: solves KiwiFlare, gets CSRF, POSTs creds.
// Caller must hold mu or be in a single-threaded context (NewSessionService).
func (s *SessionService) Login(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login(ctx)
}

func (s *SessionService) login(ctx context.Context) error {
	base := s.domain.String()

	log.Println("🔑 Priming KiwiFlare clearance...")
	resp, err := s.get(ctx, s.domain)
	if err != nil {
		return fmt.Errorf("root GET: %w", err)
	}
	resp.Body.Close()
	log.Println("✅ Clearance primed")

	loginURL, _ := url.Parse(base + "login")
	resp, err = s.get(ctx, loginURL)
	if err != nil {
		return fmt.Errorf("login page GET: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	csrf := extractCSRF(string(body))
	if csrf == "" {
		return fmt.Errorf("CSRF token not found")
	}
	log.Printf("🔐 CSRF token obtained: %s...", csrf[:min(10, len(csrf))])

	form := url.Values{
		"_xfToken":    {csrf},
		"login":       {s.username},
		"password":    {s.password},
		"_xfRedirect": {base},
		"remember":    {"1"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"login/login",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", base+"login")
	req.Header.Set("Origin", strings.TrimSuffix(base, "/"))

	postResp, err := s.do(req)
	if err != nil {
		return fmt.Errorf("login POST: %w", err)
	}
	postResp.Body.Close()

	if s.cookies["xf_user"] == "" {
		return fmt.Errorf("xf_user not set after login — check credentials")
	}
	log.Println("✅ xf_user cookie obtained")
	return nil
}

// Refresh gets a fresh xf_session. Falls back to full re-login if xf_user lost.
// Mirrors sockchat's kf.RefreshSession() call in connect().
func (s *SessionService) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("🔄 Refreshing session...")
	s.setCookie("xf_session", "")

	resp, err := s.get(ctx, s.domain)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if s.cookies["xf_user"] == "" {
		log.Println("⚠️ xf_user lost — re-logging in...")
		return s.login(ctx)
	}

	log.Println("✅ Session refreshed")
	return nil
}

// CookieString returns current cookies as a Cookie header value.
// ttrs_clearance is intentionally excluded — it must be solved fresh
// per-endpoint before each WebSocket connection attempt.
func (s *SessionService) CookieString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cookieHeader()
}

// CookieStringForWS returns cookies for the WebSocket dial with ttrs_clearance
// excluded. The caller must solve the clearance challenge for the WS endpoint
// first and inject it directly into the dial headers.
func (s *SessionService) CookieStringForWS() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := make([]string, 0, len(s.cookies))
	for k, v := range s.cookies {
		if v != "" && k != "ttrs_clearance" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// SolveForHost solves a KiwiFlare 203 challenge from a non-standard port
// endpoint (e.g. the WebSocket on 9443). The challenge body is parsed locally
// but the solution is always submitted to port 443 — mirroring sockchat's
// behaviour via cerberus, whose postSolution uses Hostname() (strips port).
// The clearance issued by 443 is accepted by 9443.
func (s *SessionService) SolveForHost(ctx context.Context, body []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	before := s.cookies["ttrs_clearance"]
	// Always submit to the base domain on port 443.
	if err := s.solveAndSubmit(ctx, body, s.domain.Hostname()); err != nil {
		return "", err
	}
	after := s.cookies["ttrs_clearance"]
	if after == before {
		return "", fmt.Errorf("ttrs_clearance unchanged after solve — submit may have failed")
	}
	return after, nil
}

// --- PoW solver ---

func parseChallengeHTML(body string) (salt string, diff uint32, err error) {
	sm := regexp.MustCompile(`data-ttrs-challenge=["']([^"']+)["']`).FindStringSubmatch(body)
	dm := regexp.MustCompile(`data-ttrs-difficulty=["'](\d+)["']`).FindStringSubmatch(body)
	if len(sm) < 2 || len(dm) < 2 {
		return "", 0, fmt.Errorf("challenge attributes not found in HTML")
	}
	var d int
	fmt.Sscanf(dm[1], "%d", &d)
	return sm[1], uint32(d), nil
}

func solvePoW(ctx context.Context, salt string, difficulty uint32) (uint64, error) {
	nbytes := difficulty / 8
	rem := difficulty % 8
	var mask byte
	for i := uint32(0); i < rem; i++ {
		mask = (mask << 1) | 1
	}
	if rem > 0 {
		mask <<= 8 - rem
	}

	var nonce uint64
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		nonce++
		h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", salt, nonce)))
		if leadingZeros(h[:], nbytes, rem, mask) {
			return nonce, nil
		}
	}
}

func leadingZeros(hash []byte, nbytes, rem uint32, mask byte) bool {
	for i := uint32(0); i < nbytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	return hash[nbytes]&mask == 0
}

// --- helpers ---

func extractCSRF(body string) string {
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`"csrf":"([^"]+)"`),
		regexp.MustCompile(`XF\.config\.csrf\s*=\s*"([^"]+)"`),
	} {
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
