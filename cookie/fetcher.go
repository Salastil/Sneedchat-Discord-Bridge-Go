package cookie

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	CookieRefreshInterval = 4 * time.Hour
	CookieRetryDelay      = 5 * time.Second
	MaxCookieRetryDelay   = 60 * time.Second
)

type CookieRefreshService struct {
	username      string
	password      string
	domain        string
	client        *http.Client
	jar           http.CookieJar
	currentCookie string

	debug bool

	mu        sync.RWMutex
	readyOnce sync.Once
	readyCh   chan struct{}
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewCookieRefreshService(username, password, domain string) (*CookieRefreshService, error) {
	return NewCookieRefreshServiceWithDebug(username, password, domain, false)
}

func NewCookieRefreshServiceWithDebug(username, password, domain string, debug bool) (*CookieRefreshService, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{} 
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	return &CookieRefreshService{
		username: username,
		password: password,
		domain:   domain,
		client:   client,
		jar:      jar,
		debug:    debug,
		readyCh:  make(chan struct{}),
		stopCh:   make(chan struct{}),
	}, nil
}

func (s *CookieRefreshService) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Println("⏳ Fetching initial cookie...")
		c, err := s.FetchFreshCookie()
		if err != nil {
			log.Printf("❌ Failed to obtain initial cookie: %v", err)
			s.readyOnce.Do(func() { close(s.readyCh) })
			return
		}
		s.mu.Lock()
		s.currentCookie = c
		s.mu.Unlock()
		s.readyOnce.Do(func() { close(s.readyCh) })
	}()
}

func (s *CookieRefreshService) WaitForCookie() {
	<-s.readyCh
}

func (s *CookieRefreshService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

func (s *CookieRefreshService) GetCurrentCookie() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentCookie
}
func (s *CookieRefreshService) FetchFreshCookie() (string, error) {
	if s.debug {
		log.Println("💡 Stage: Starting FetchFreshCookie")
	}

	attempt := 0
	delay := CookieRetryDelay

	for {
		attempt++
		c, err := s.attemptFetchCookie()
		if err == nil {
			if s.debug {
				log.Printf("✅ Successfully fetched fresh cookie with xf_user (attempt %d)", attempt)
			}
			return c, nil
		}

		log.Printf("⚠️ Cookie fetch attempt %d failed: %v", attempt, err)
		// Exponential backoff, capped
		time.Sleep(delay)
		delay *= 2
		if delay > MaxCookieRetryDelay {
			delay = MaxCookieRetryDelay
		}
	}
}

func (s *CookieRefreshService) attemptFetchCookie() (string, error) {
	base := fmt.Sprintf("https://%s/", s.domain)
	loginPage := fmt.Sprintf("https://%s/login", s.domain)
	loginPost := fmt.Sprintf("https://%s/login/login", s.domain)
	accountURL := fmt.Sprintf("https://%s/account/", s.domain)
	rootURL, _ := url.Parse(base)

	// Reset redirect policy for manual control
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// don't auto-follow on login POST so we can inspect cookies first
		return http.ErrUseLastResponse
	}

	// --- Step 1: KiwiFlare
	if s.debug {
		log.Println("Step 1: Checking for KiwiFlare challenge...")
	}
	if err := s.solveKiwiFlareIfPresent(base); err != nil {
		return "", fmt.Errorf("KiwiFlare solve failed: %w", err)
	}
	if s.debug {
		log.Println("✅ KiwiFlare challenge solved")
	}

	time.Sleep(2 * time.Second)

	// --- Step 2: GET /login ---
	if s.debug {
		log.Println("Step 2: Fetching login page...")
	}
	reqLogin, _ := http.NewRequest("GET", loginPage, nil)
	reqLogin.Header.Set("Cache-Control", "no-cache")
	reqLogin.Header.Set("Pragma", "no-cache")
	reqLogin.Header.Set("User-Agent", "Mozilla/5.0")
	respLogin, err := s.client.Do(reqLogin)
	if err != nil {
		return "", fmt.Errorf("failed to get login page: %w", err)
	}
	defer respLogin.Body.Close()

	bodyLogin, _ := io.ReadAll(respLogin.Body)
	if s.debug {
		log.Printf("📄 Login page HTML (first 1024 bytes):\n%s", firstN(string(bodyLogin), 1024))
	}

	// --- Step 3: Extract CSRF---
	if s.debug {
		log.Println("Step 3: Extracting CSRF token...")
	}
	csrf := extractCSRF(string(bodyLogin))
	if csrf == "" {
		return "", fmt.Errorf("CSRF token not found in login page")
	}
	if s.debug {
		log.Printf("✅ Found CSRF token: %s...", abbreviate(csrf, 10))
	}

	// Record if already have xf_user BEFORE login POST
	preCookies := s.jar.Cookies(rootURL)
	hadXfUserBefore := hasCookie(preCookies, "xf_user")

	// --- Step 4: POST /login/login---
	if s.debug {
		log.Println("Step 4: Submitting login credentials...")
		logCookies("Cookies before login POST", preCookies)
	}

	form := url.Values{
		"_xfToken":    {csrf},
		"login":       {s.username},
		"password":    {s.password},
		"_xfRedirect": {base},
		"remember":    {"1"},
	}
	postReq, _ := http.NewRequest("POST", loginPost, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", "Mozilla/5.0")
	postReq.Header.Set("Referer", loginPage)
	postReq.Header.Set("Origin", fmt.Sprintf("https://%s", s.domain))
	postResp, err := s.client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("login POST failed: %w", err)
	}
	defer postResp.Body.Close()

	if s.debug {
		log.Printf("Login response status: %d", postResp.StatusCode)
	}

	// XenForo often 303 when successful; 200 might still be fine (AJAX template), so we don't fail on 200 alone.

	// small delay to let cookies propagate
	if s.debug {
		log.Println("⏳ Waiting 2 seconds for XenForo to issue cookies...")
	}
	time.Sleep(2 * time.Second)

	postCookies := s.jar.Cookies(rootURL)
	if s.debug {
		for _, c := range postCookies {
			log.Printf("Cookie after login: %s=%s...", c.Name, abbreviate(c.Value, 10))
		}
	}

	// Check for xf_user after login
	if hasCookie(postCookies, "xf_user") {
		return buildCookieString(postCookies), nil
	}

	// ---- Success path: If we had xf_user before and still no new xf_user now,
	// try validating the existing session on /account/ and succeed if logged in.
	if hadXfUserBefore {
		if s.debug {
			log.Println("🔍 Missing xf_user after login POST but it existed before; validating current session via /account/ ...")
		}
		ok, cookieStr := s.validateSessionUsingAccount(accountURL, rootURL)
		if ok {
			if s.debug {
				log.Println("✅ /account/ shows logged-in; retaining existing session cookie")
			}
			return cookieStr, nil
		}
		if s.debug {
			log.Println("⚠️ /account/ did not confirm logged-in; proceeding with failure")
		}
	}

	// If not successful yet, read body for context & fail
	bodyBytes, _ := io.ReadAll(postResp.Body)
	bodyText := string(bodyBytes)
	if s.debug {
		log.Printf("📄 Login HTML snippet (first 500 chars):\n%s", firstN(bodyText, 500))
	}
	return "", fmt.Errorf("retry still missing xf_user cookie")
}

// -------------------------------------------
// KiwiFlare handling
// -------------------------------------------
func (s *CookieRefreshService) solveKiwiFlareIfPresent(base string) error {
	req, _ := http.NewRequest("GET", base, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// Look for data-sssg-challenge and difficulty
	re := regexp.MustCompile(`data-sssg-challenge=["']([0-9a-fA-F]+)["'][^>]*data-sssg-difficulty=["'](\d+)["']`)
	m := re.FindStringSubmatch(html)
	if len(m) < 3 {
		if s.debug {
			log.Println("No KiwiFlare POW detected")
		}
		return nil
	}
	token := m[1]
	diff, _ := strconv.Atoi(m[2])

	if s.debug {
		log.Printf("Solving KiwiFlare challenge (difficulty=%d, token=%s...)", diff, abbreviate(token, 10))
	}
	nonce, dur, err := s.solvePoW(token, diff)
	if err != nil {
		return err
	}
	if s.debug {
		log.Printf("✅ KiwiFlare challenge solved in %v (nonce=%s)", dur, nonce)
	}

	// Submit solution
	answerURL := fmt.Sprintf("https://%s/.sssg/api/answer", s.domain)
	form := url.Values{"a": {token}, "b": {nonce}}
	subReq, _ := http.NewRequest("POST", answerURL, strings.NewReader(form.Encode()))
	subReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	subReq.Header.Set("User-Agent", "Mozilla/5.0")
	subResp, err := s.client.Do(subReq)
	if err != nil {
		return err
	}
	defer subResp.Body.Close()

	if subResp.StatusCode != 200 {
		body, _ := io.ReadAll(subResp.Body)
		return fmt.Errorf("challenge solve HTTP %d (%s)", subResp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Check jar for sssg_clearance
	rootURL, _ := url.Parse(fmt.Sprintf("https://%s/", s.domain))
	for _, c := range s.jar.Cookies(rootURL) {
		if c.Name == "sssg_clearance" {
			if s.debug {
				log.Printf("✅ KiwiFlare clearance cookie confirmed: %s...", abbreviate(c.Value, 10))
			}
			break
		}
	}

	time.Sleep(2 * time.Second)
	return nil
}

func (s *CookieRefreshService) solvePoW(token string, difficulty int) (string, time.Duration, error) {
	start := time.Now()
	nonce := rand.Int63()
	requiredBytes := difficulty / 8
	requiredBits := difficulty % 8
	const maxAttempts = 10_000_000

	for attempts := 0; attempts < maxAttempts; attempts++ {
		nonce++
		input := token + fmt.Sprintf("%d", nonce)
		sum := sha256.Sum256([]byte(input))

		// Check leading zero bits
		ok := true
		for i := 0; i < requiredBytes; i++ {
			if sum[i] != 0 {
				ok = false
				break
			}
		}
		if ok && requiredBits > 0 && requiredBytes < len(sum) {
			mask := byte(0xFF << (8 - requiredBits))
			if sum[requiredBytes]&mask != 0 {
				ok = false
			}
		}
		if ok {
			elapsed := time.Since(start)
			// Stretch to >= ~1.7s to look human
			if elapsed < 1700*time.Millisecond {
				time.Sleep(1700*time.Millisecond - elapsed)
				elapsed = 1700 * time.Millisecond
			}
			return fmt.Sprintf("%d", nonce), elapsed, nil
		}
	}
	return "", 0, fmt.Errorf("failed to solve PoW within %d attempts", maxAttempts)
}

func extractCSRF(body string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`"csrf":"([^"]+)"`),
		regexp.MustCompile(`XF\.config\.csrf\s*=\s*"([^"]+)"`),
	}
	for _, re := range patterns {
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name {
			return true
		}
	}
	return false
}

func buildCookieString(cookies []*http.Cookie) string {
	want := map[string]bool{
		"sssg_clearance": true,
		"xf_csrf":        true,
		"xf_session":     true,
		"xf_user":        true,
		"xf_toggle":      true,
	}
	var parts []string
	for _, c := range cookies {
		if want[c.Name] {
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	return strings.Join(parts, "; ")
}

func (s *CookieRefreshService) validateSessionUsingAccount(accountURL string, rootURL *url.URL) (bool, string) {
	if s.debug {
		log.Println("🔍 Validating session via /account/ ...")
	}
	req, _ := http.NewRequest("GET", accountURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := s.client.Do(req)
	if err != nil {
		if s.debug {
			log.Printf("⚠️ /account/ request error: %v", err)
		}
		return false, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	snippet := firstN(string(body), 500)

	if s.debug {
		log.Printf("🔍 Accessed /account/ (%d)", resp.StatusCode)
		log.Printf("📄 /account/ HTML snippet:\n%s", snippet)
		for _, c := range s.jar.Cookies(rootURL) {
			log.Printf("🍪 Cookie after /account/: %s=%s...", c.Name, abbreviate(c.Value, 10))
		}
	}

	// Consider logged-in if data-logged-in="true" or the template isn't "login"
	if strings.Contains(snippet, `data-logged-in="true"`) ||
		(!strings.Contains(snippet, `data-template="login"`) && resp.StatusCode == 200) {
		return true, buildCookieString(s.jar.Cookies(rootURL))
	}
	return false, ""
}

func logCookies(prefix string, cookies []*http.Cookie) {
	log.Printf("%s (%d):", prefix, len(cookies))
	for _, c := range cookies {
		log.Printf("  - %s = %s...", c.Name, abbreviate(c.Value, 10))
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func abbreviate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
