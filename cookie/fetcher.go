package cookie

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	CookieRetryDelay    = 5 * time.Second
	MaxCookieRetryDelay = 60 * time.Second
	CookieRefreshEvery  = 4 * time.Hour
)

type RefreshService struct {
	username, password, domain string
	client                     *http.Client

	cookieMu      sync.RWMutex
	currentCookie string

	readyOnce sync.Once
	readyCh   chan struct{}

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewRefreshService(username, password, domain string) *RefreshService {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		// Force HTTP/1.1 (avoid ALPN h2 differences)
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{
		Jar:       jar,
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	return &RefreshService{
		username: username,
		password: password,
		domain:   domain,
		client:   client,
		readyCh:  make(chan struct{}),
		stopCh:   make(chan struct{}),
	}
}

func (r *RefreshService) Start() {
	r.wg.Add(1)
	go r.loop()
}

func (r *RefreshService) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

func (r *RefreshService) WaitForCookie() { <-r.readyCh }

func (r *RefreshService) GetCurrentCookie() string {
	r.cookieMu.RLock()
	defer r.cookieMu.RUnlock()
	return r.currentCookie
}

func (r *RefreshService) loop() {
	defer r.wg.Done()

	log.Println("🔑 Fetching initial cookie...")
	c, err := r.FetchFreshCookie()
	if err != nil {
		log.Printf("❌ Failed to acquire initial cookie: %v", err)
		return
	}
	r.cookieMu.Lock()
	r.currentCookie = c
	r.cookieMu.Unlock()
	r.readyOnce.Do(func() { close(r.readyCh) })
	log.Println("✅ Initial cookie acquired")
}

func (r *RefreshService) FetchFreshCookie() (string, error) {
	attempt := 0
	delay := CookieRetryDelay
	for {
		select {
		case <-r.stopCh:
			return "", fmt.Errorf("stopped")
		default:
		}

		attempt++
		if attempt > 1 {
			log.Printf("🔄 Cookie fetch retry attempt %d (waiting %v)...", attempt, delay)
			time.Sleep(delay)
			delay *= 2
			if delay > MaxCookieRetryDelay {
				delay = MaxCookieRetryDelay
			}
		}

		c, err := r.attemptFetchCookie()
		if err != nil {
			log.Printf("⚠️ Cookie fetch attempt %d failed: %v", attempt, err)
			continue
		}
		if strings.Contains(c, "xf_user=") {
			log.Printf("✅ Successfully fetched fresh cookie with xf_user (attempt %d)", attempt)
			r.cookieMu.Lock()
			r.currentCookie = c
			r.cookieMu.Unlock()
			return c, nil
		}
		log.Printf("❌ Cookie fetch attempt %d missing xf_user — retrying...", attempt)
	}
}

func (r *RefreshService) attemptFetchCookie() (string, error) {
	// Step 1: KiwiFlare
	log.Println("Step 1: Checking for KiwiFlare challenge...")
	clearance, err := r.getClearanceToken()
	if err != nil {
		return "", fmt.Errorf("clearance token error: %w", err)
	}
	if clearance != "" {
		log.Println("✅ KiwiFlare challenge solved")
		log.Println("⏳ Waiting 2 seconds for cookie propagation...")
		time.Sleep(2 * time.Second)
	}

	// Step 2: GET /login
	log.Println("Step 2: Fetching login page...")
	loginURL := fmt.Sprintf("https://%s/login/", r.domain)
	req, _ := http.NewRequest("GET", loginURL, nil)
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.URL.RawQuery = fmt.Sprintf("r=%d", rand.Intn(1_000_000))

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get login page: %w", err)
	}
	defer resp.Body.Close()
	log.Printf("→ Using protocol for login page: %s", resp.Proto)

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	log.Println("⏳ Waiting 1 second before processing login page...")
	time.Sleep(1 * time.Second)

	// Step 3: Extract CSRF
	log.Println("Step 3: Extracting CSRF token...")
	var csrf string
	for _, pat := range []*regexp.Regexp{
		regexp.MustCompile(`<html[^>]*data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`name="_xfToken" value="([^"]+)"`),
		regexp.MustCompile(`data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`"csrf":"([^"]+)"`),
		regexp.MustCompile(`XF\.config\.csrf\s*=\s*"([^"]+)"`),
	} {
		if m := pat.FindStringSubmatch(bodyStr); len(m) >= 2 {
			csrf = m[1]
			break
		}
	}
	if csrf == "" {
		log.Printf("⚠️ CSRF token not found. Partial HTML:\n%s", bodyStr[:min(800, len(bodyStr))])
		return "", fmt.Errorf("CSRF token not found in login page")
	}
	log.Printf("✅ Found CSRF token: %s...", csrf[:min(10, len(csrf))])

	// Step 4: POST /login/login
	log.Println("Step 4: Submitting login credentials...")
	postURL := fmt.Sprintf("https://%s/login/login", r.domain)
	form := url.Values{
		"_xfToken":      {csrf},
		"_xfRequestUri": {"/"},
		"_xfWithData":   {"1"},
		"login":         {r.username},
		"password":      {r.password},
		"_xfRedirect":   {fmt.Sprintf("https://%s/", r.domain)},
		"remember":      {"1"},
	}

	// ensure GET cookies are kept
	cookieURL, _ := url.Parse(fmt.Sprintf("https://%s/", r.domain))
	if resp.Cookies() != nil {
		r.client.Jar.SetCookies(cookieURL, resp.Cookies())
	}

	postReq, _ := http.NewRequest("POST", postURL, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", randomUserAgent())
	postReq.Header.Set("Referer", loginURL)
	postReq.Header.Set("Origin", fmt.Sprintf("https://%s", r.domain))
	postReq.Header.Set("X-XF-Token", csrf)
	postReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	postReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	postReq.Header.Set("Accept-Encoding", "gzip, deflate") // avoid br

	loginResp, err := r.client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("login POST failed: %w", err)
	}
	defer loginResp.Body.Close()
	log.Printf("Login response status: %d", loginResp.StatusCode)

	// Follow a single redirect (XenForo usually sets xf_user on redirect target)
	if loginResp.StatusCode >= 300 && loginResp.StatusCode < 400 {
		if loc := loginResp.Header.Get("Location"); loc != "" {
			log.Printf("Following redirect to %s to check for xf_user...", loc)
			url2 := loc
			if !strings.HasPrefix(loc, "http") {
				url2 = fmt.Sprintf("https://%s%s", r.domain, loc)
			}
			time.Sleep(1 * time.Second)
			if fr, err := r.client.Get(url2); err == nil {
				fr.Body.Close()
				time.Sleep(500 * time.Millisecond)
			}
		}
	}

	// Decode response (gzip)
	var reader io.ReadCloser
	if loginResp.Header.Get("Content-Encoding") == "gzip" {
		gz, ge := gzip.NewReader(loginResp.Body)
		if ge == nil {
			reader = gz
			defer gz.Close()
		} else {
			reader = io.NopCloser(loginResp.Body)
		}
	} else {
		reader = io.NopCloser(loginResp.Body)
	}
	respHTML, _ := io.ReadAll(reader)
	if strings.Contains(string(respHTML), `data-logged-in="false"`) {
		log.Println("⚠️ HTML indicates still logged out (data-logged-in=false)")
		time.Sleep(1 * time.Second)
		return r.retryWithFreshCSRF()
	}

	// Normalize cookie domains and compose cookie string
	cookies := r.client.Jar.Cookies(cookieURL)
	for _, c := range cookies {
		c.Domain = strings.TrimPrefix(c.Domain, ".")
	}
	r.client.Jar.SetCookies(cookieURL, cookies)

	want := map[string]bool{
		"xf_user":        true,
		"xf_toggle":      true,
		"xf_csrf":        true,
		"xf_session":     true,
		"sssg_clearance": true,
	}
	var parts []string
	hasUser := false
	for _, c := range cookies {
		if want[c.Name] {
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
			if c.Name == "xf_user" {
				hasUser = true
			}
		}
	}
	if !hasUser {
		return "", fmt.Errorf("xf_user cookie missing — authentication failed, will retry")
	}
	return strings.Join(parts, "; "), nil
}

func randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	}
	return agents[rand.Intn(len(agents))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
