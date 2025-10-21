package cookie

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
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

// CookieRefreshService manages periodic cookie refreshing.
type CookieRefreshService struct {
	username      string
	password      string
	domain        string
	client        *http.Client
	debug         bool
	currentCookie string
	cookieMu      sync.RWMutex
	cookieReady   chan struct{}
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// NewCookieRefreshService initializes a new cookie service.
func NewCookieRefreshService(username, password, domain string, debug bool) (*CookieRefreshService, error) {
	// Standard cookie jar (no additional dependencies needed)
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// Configure TLS to match Python's behavior
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		// Support modern cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	// Configure transport to match Python's behavior
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true, // Force HTTP/2 like Python's aiohttp
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Jar:       jar,
		Timeout:   45 * time.Second,
		Transport: transport,
		// CRITICAL: Disable automatic redirects - we handle them manually
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &CookieRefreshService{
		username:    username,
		password:    password,
		domain:      domain,
		client:      client,
		debug:       debug,
		cookieReady: make(chan struct{}),
		stopChan:    make(chan struct{}),
	}, nil
}

//
// ---------- Public methods ----------
//

func (crs *CookieRefreshService) Start() {
	crs.wg.Add(1)
	go crs.refreshLoop()
}

func (crs *CookieRefreshService) Stop() {
	close(crs.stopChan)
	crs.wg.Wait()
}

func (crs *CookieRefreshService) WaitForCookie() {
	<-crs.cookieReady
}

func (crs *CookieRefreshService) GetCurrentCookie() string {
	crs.cookieMu.RLock()
	defer crs.cookieMu.RUnlock()
	return crs.currentCookie
}

//
// ---------- Internal core ----------
//

func (crs *CookieRefreshService) refreshLoop() {
	defer crs.wg.Done()

	log.Println("🔑 Fetching initial cookie...")
	fresh, err := crs.FetchFreshCookie()
	if err != nil {
		log.Printf("❌ Initial cookie fetch failed: %v", err)
		return
	}

	crs.cookieMu.Lock()
	crs.currentCookie = fresh
	crs.cookieMu.Unlock()
	close(crs.cookieReady)
	log.Println("✅ Initial cookie acquired")

	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("🔄 Automatic cookie refresh cycle started")
			cookie, err := crs.FetchFreshCookie()
			if err != nil {
				log.Printf("⚠️ Cookie refresh failed: %v", err)
				continue
			}
			crs.cookieMu.Lock()
			crs.currentCookie = cookie
			crs.cookieMu.Unlock()
			log.Println("✅ Cookie refresh completed")

		case <-crs.stopChan:
			return
		}
	}
}

// FetchFreshCookie attempts full login until success.
func (crs *CookieRefreshService) FetchFreshCookie() (string, error) {
	attempt := 1
	for {
		log.Printf("🔑 Attempting cookie fetch (attempt %d)", attempt)
		cookie, err := crs.attemptFetchCookie()
		if err == nil && strings.Contains(cookie, "xf_user=") {
			log.Printf("✅ Successfully fetched fresh cookie with xf_user (attempt %d)", attempt)
			return cookie, nil
		}

		if err != nil {
			log.Printf("⚠️ Cookie fetch attempt %d failed: %v", attempt, err)
		} else {
			log.Printf("⚠️ Cookie fetch attempt %d failed: retry still missing xf_user cookie", attempt)
		}

		time.Sleep(5 * time.Second)
		attempt++
	}
}

// attemptFetchCookie performs one complete login cycle.
func (crs *CookieRefreshService) attemptFetchCookie() (string, error) {
	baseURL := fmt.Sprintf("https://%s", crs.domain)
	
	// Validate credentials
	if crs.username == "" || crs.password == "" {
		return "", fmt.Errorf("username or password is empty")
	}
	
	if crs.debug {
		log.Printf("🔐 Attempting login for user: '%s' (password length: %d)", crs.username, len(crs.password))
	}

	// Step 1: KiwiFlare clearance
	log.Println("Step 1: Checking for KiwiFlare challenge...")
	req, _ := http.NewRequest("GET", baseURL+"/", nil)
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	start := time.Now()
	resp, err := crs.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("initial GET failed: %w", err)
	}
	defer resp.Body.Close()

	if crs.debug {
		log.Printf("📩 [HTTP GET] %s/ -> %d %s", baseURL, resp.StatusCode, resp.Status)
		for k, v := range resp.Header {
			for _, val := range v {
				log.Printf("   ← %s: %s", k, val)
			}
		}
	}

	body, _ := io.ReadAll(resp.Body)
	log.Printf("⏱️ KiwiFlare challenge page loaded in %v", time.Since(start))
	log.Printf("📄 Body length: %d bytes", len(body))

	if strings.Contains(string(body), "data-sssg-challenge") {
		auth, err := crs.solveKiwiFlare(body)
		if err != nil {
			return "", fmt.Errorf("KiwiFlare solve error: %w", err)
		}
		log.Printf("✅ KiwiFlare clearance cookie confirmed: %s...", trimLong(auth, 10))
		log.Println("✅ KiwiFlare challenge solved")
		log.Println("⏳ Waiting 2 seconds for cookie propagation...")
		time.Sleep(2 * time.Second)
	}

	// Step 2: Login page
	log.Println("Step 2: Fetching login page...")
	loginURL := fmt.Sprintf("%s/login", baseURL)
	req, _ = http.NewRequest("GET", loginURL, nil)
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err = crs.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get login page: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	log.Printf("→ Using protocol for login page: %s", resp.Proto)
	time.Sleep(1 * time.Second)

	// Step 3: Extract CSRF token
	csrfToken := extractCSRF(string(body))
	if csrfToken == "" {
		if crs.debug {
			log.Printf("🔍 HTML body (first 2000 chars):\n%s", string(body)[:min(2000, len(body))])
		}
		return "", fmt.Errorf("missing CSRF token")
	}
	log.Printf("✅ Found CSRF token: %s...", trimLong(csrfToken, 10))

	// Step 4: POST login credentials (matching Python exactly)
	loginPost := fmt.Sprintf("%s/login/login", baseURL)
	
	// Build form data exactly like Python
	data := url.Values{
		"_xfToken": {csrfToken},
		"login":    {crs.username},
		"password": {crs.password},
		"remember": {"1"},
	}
	
	// Add redirect URL as separate parameter (without the key from Python that was causing issues)
	data.Set("_xfRedirect", baseURL+"/")
	
	formData := data.Encode()
	
	if crs.debug {
		log.Printf("🔐 POST form data: %s", strings.ReplaceAll(formData, crs.password, "***"))
	}

	postReq, _ := http.NewRequest("POST", loginPost, strings.NewReader(formData))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(formData)))
	postReq.Header.Set("User-Agent", randomUserAgent())
	postReq.Header.Set("Referer", loginURL)
	postReq.Header.Set("Origin", baseURL)
	postReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	postReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
	postReq.Header.Set("Accept-Encoding", "gzip, deflate, br")
	postReq.Header.Set("Connection", "keep-alive")
	postReq.Header.Set("Upgrade-Insecure-Requests", "1")
	postReq.Header.Set("Cache-Control", "max-age=0")

	loginResp, err := crs.client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("login POST failed: %w", err)
	}
	defer loginResp.Body.Close()

	log.Printf("Login POST response: %d %s (proto: %s)", loginResp.StatusCode, loginResp.Status, loginResp.Proto)
	
	if crs.debug {
		log.Println("Login response headers:")
		for k, v := range loginResp.Header {
			for _, val := range v {
				log.Printf("   ← %s: %s", k, val)
			}
		}
	}

	// Check if we got a redirect (successful login returns 303)
	if loginResp.StatusCode >= 300 && loginResp.StatusCode < 400 {
		location := loginResp.Header.Get("Location")
		log.Printf("✅ Login successful - got redirect to: %s", location)
		io.Copy(io.Discard, loginResp.Body)
	} else if loginResp.StatusCode == 200 {
		// Status 200 on login POST might mean:
		// 1. Failed login (shows error)
		// 2. Already logged in / session reuse
		// 3. Two-factor auth required
		bodyBytes, _ := io.ReadAll(loginResp.Body)
		snippet := string(bodyBytes)
		
		// Check what kind of 200 response this is
		isLoggedIn := strings.Contains(snippet, "data-logged-in=\"true\"")
		hasError := strings.Contains(snippet, "Incorrect password") || 
		            strings.Contains(snippet, "requested user") ||
		            strings.Contains(snippet, "error")
		
		if isLoggedIn {
			log.Println("✅ Login successful - already authenticated (200 OK with logged-in=true)")
		} else if !hasError {
			// No error message but not logged in = might be session propagation delay
			log.Println("⚠️ Login POST returned 200 without errors - checking session state...")
		} else if strings.Contains(snippet, "Incorrect password") {
			return "", fmt.Errorf("login failed: incorrect password")
		} else if strings.Contains(snippet, "requested user") {
			return "", fmt.Errorf("login failed: user not found")
		} else {
			log.Println("⚠️ Login POST returned 200 with possible error - will check cookies")
		}
		
		if crs.debug && len(snippet) > 1000 {
			snippet = snippet[:1000]
		}
		if crs.debug {
			log.Printf("🧩 Login 200 body snippet:\n%s", snippet)
		}
	} else {
		// Other status codes
		io.Copy(io.Discard, loginResp.Body)
		log.Printf("⚠️ Unexpected login response: %d %s", loginResp.StatusCode, loginResp.Status)
	}

	time.Sleep(3 * time.Second) // Increased from 2s - give server more time

	// Step 5: Manually extract Set-Cookie headers from POST response
	// This is critical - Go's cookie jar might not automatically process
	// Set-Cookie headers when we disable redirects
	log.Println("Step 5: Extracting cookies from POST response headers...")
	if setCookies := loginResp.Header["Set-Cookie"]; len(setCookies) > 0 {
		for _, sc := range setCookies {
			log.Printf("📩 Set-Cookie header: %s", trimLong(sc, 80))
			// Parse and add to jar manually if needed
			// The jar should do this automatically, but let's be explicit
		}
	}
	
	// Step 6: Check cookies in jar
	cookieURL, _ := url.Parse(baseURL)
	cookies := crs.client.Jar.Cookies(cookieURL)
	hasXfUser := false
	hasXfSession := false
	for _, c := range cookies {
		log.Printf("🍪 [After Login POST] %s=%s", c.Name, trimLong(c.Value, 10))
		if c.Name == "xf_user" {
			hasXfUser = true
		}
		if c.Name == "xf_session" {
			hasXfSession = true
		}
	}
	
	// If we have xf_session but not xf_user, login succeeded but we need to trigger xf_user
	if hasXfSession && !hasXfUser {
		log.Println("✅ Login successful (have xf_session) - will trigger xf_user cookie")
	} else if !hasXfSession {
		log.Println("❌ Login may have failed - no xf_session cookie present")
		return "", fmt.Errorf("login failed - no session cookie received")
	}

	// Step 6: CRITICAL - Manually follow redirects if xf_user missing (Python does this automatically)
	maxRedirects := 5
	redirectCount := 0
	currentURL := baseURL + "/"

	for !hasXfUser && redirectCount < maxRedirects {
		redirectCount++
		log.Printf("🧭 Following redirect manually (attempt %d) to capture xf_user...", redirectCount)
		time.Sleep(1 * time.Second)

		followReq, _ := http.NewRequest("GET", currentURL, nil)
		followReq.Header.Set("User-Agent", randomUserAgent())
		followReq.Header.Set("Referer", loginPost)
		followReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		followReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
		followReq.Header.Set("Connection", "keep-alive")
		followReq.Header.Set("Upgrade-Insecure-Requests", "1")

		followResp, ferr := crs.client.Do(followReq)
		if ferr != nil {
			log.Printf("⚠️ Redirect follow failed: %v", ferr)
			break
		}

		log.Printf("📩 [HTTP GET] %s -> %s (proto: %s)", currentURL, followResp.Status, followResp.Proto)

		// Check for additional redirects
		if followResp.StatusCode >= 300 && followResp.StatusCode < 400 {
			location := followResp.Header.Get("Location")
			if location != "" {
				if !strings.HasPrefix(location, "http") {
					location = baseURL + location
				}
				currentURL = location
				log.Printf("🔄 Server returned redirect to: %s", currentURL)
			}
		}

		io.Copy(io.Discard, followResp.Body)
		followResp.Body.Close()
		time.Sleep(1 * time.Second)

		// Check cookies again
		cookies = crs.client.Jar.Cookies(cookieURL)
		for _, c := range cookies {
			log.Printf("🍪 [After Redirect %d] %s=%s", redirectCount, c.Name, trimLong(c.Value, 10))
			if c.Name == "xf_user" {
				hasXfUser = true
				break
			}
		}

		if hasXfUser {
			log.Println("✅ xf_user cookie acquired after redirect follow")
			break
		}
	}

	// Step 7: Secondary check — trigger /account/ to issue xf_user if still missing
	// CRITICAL: For rooms that don't require auth to view, we need to force
	// session validation by accessing an authenticated endpoint
	if !hasXfUser {
		log.Println("🧭 Performing secondary authenticated fetch to /account/ to trigger xf_user...")
		time.Sleep(2 * time.Second) // Increased wait time for session propagation

		accountReq, _ := http.NewRequest("GET", baseURL+"/account/", nil)
		accountReq.Header.Set("User-Agent", randomUserAgent())
		accountReq.Header.Set("Referer", loginPost)
		accountReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		accountReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
		accountReq.Header.Set("Connection", "keep-alive")
		accountReq.Header.Set("Upgrade-Insecure-Requests", "1")

		accountResp, accErr := crs.client.Do(accountReq)
		if accErr != nil {
			log.Printf("⚠️ Account fetch failed: %v", accErr)
		} else {
			io.Copy(io.Discard, accountResp.Body)
			accountResp.Body.Close()
			log.Printf("📩 [HTTP GET] %s/account/ -> %s", baseURL, accountResp.Status)
		}
		time.Sleep(2 * time.Second) // Additional wait after /account/ fetch

		cookies = crs.client.Jar.Cookies(cookieURL)
		for _, c := range cookies {
			log.Printf("🍪 [After /account/] %s=%s", c.Name, trimLong(c.Value, 10))
			if c.Name == "xf_user" {
				hasXfUser = true
			}
		}
		if hasXfUser {
			log.Println("✅ xf_user cookie acquired after /account/ fetch")
		}
	}
	
	// Step 8: FINAL ATTEMPT - Try accessing the actual forum to force session validation
	// This is critical for non-auth-required rooms like room 16
	if !hasXfUser {
		log.Println("🧭 Final attempt: accessing forum index to force session validation...")
		time.Sleep(2 * time.Second)
		
		forumReq, _ := http.NewRequest("GET", baseURL+"/forums/", nil)
		forumReq.Header.Set("User-Agent", randomUserAgent())
		forumReq.Header.Set("Referer", baseURL)
		forumReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		forumReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
		forumReq.Header.Set("Connection", "keep-alive")
		forumReq.Header.Set("Upgrade-Insecure-Requests", "1")
		
		forumResp, forumErr := crs.client.Do(forumReq)
		if forumErr != nil {
			log.Printf("⚠️ Forum fetch failed: %v", forumErr)
		} else {
			bodyBytes, _ := io.ReadAll(forumResp.Body)
			forumResp.Body.Close()
			log.Printf("📩 [HTTP GET] %s/forums/ -> %s", baseURL, forumResp.Status)
			
			// Check if we're actually logged in by looking for username in page
			if strings.Contains(string(bodyBytes), crs.username) {
				log.Println("✅ Confirmed logged in - username found in forum page")
			}
		}
		time.Sleep(2 * time.Second)
		
		cookies = crs.client.Jar.Cookies(cookieURL)
		for _, c := range cookies {
			log.Printf("🍪 [After /forums/] %s=%s", c.Name, trimLong(c.Value, 10))
			if c.Name == "xf_user" {
				hasXfUser = true
			}
		}
		if hasXfUser {
			log.Println("✅ xf_user cookie acquired after forum page fetch")
		} else {
			log.Println("⚠️ xf_user cookie still missing after all follow-ups")
			
			// Don't return error - build cookie string with what we have
			// The xf_session and xf_csrf might be enough for websocket auth
			log.Println("⚠️ Proceeding with available cookies (xf_session + xf_csrf)")
		}
	}

	// Build final cookie string
	var parts []string
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "xf_") || c.Name == "sssg_clearance" {
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	return strings.Join(parts, "; "), nil
}

//
// ---------- Utilities ----------
//

func extractCSRF(body string) string {
	reList := []*regexp.Regexp{
		regexp.MustCompile(`data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`"csrf":"([^"]+)"`),
		regexp.MustCompile(`XF\.config\.csrf\s*=\s*"([^"]+)"`),
	}
	for _, re := range reList {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func trimLong(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func randomUserAgent() string {
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	return uas[rand.Intn(len(uas))]
}

//
// ---------- KiwiFlare Solver ----------
//

func (crs *CookieRefreshService) solveKiwiFlare(body []byte) (string, error) {
	html := string(body)
	challenge := regexp.MustCompile(`data-sssg-challenge=["']([^"']+)["']`).FindStringSubmatch(html)
	difficultyStr := regexp.MustCompile(`data-sssg-difficulty=["'](\d+)["']`).FindStringSubmatch(html)
	if len(challenge) < 2 || len(difficultyStr) < 2 {
		return "", fmt.Errorf("missing challenge or difficulty")
	}
	salt := challenge[1]
	diff, _ := strconv.Atoi(difficultyStr[1])
	log.Printf("Solving KiwiFlare challenge (difficulty=%d)", diff)

	nonce := rand.Int63()
	start := time.Now()
	for {
		nonce++
		input := fmt.Sprintf("%s%d", salt, nonce)
		hash := sha256.Sum256([]byte(input))

		fullBytes := diff / 8
		remainder := diff % 8
		valid := true
		for i := 0; i < fullBytes; i++ {
			if hash[i] != 0 {
				valid = false
				break
			}
		}
		if valid && remainder > 0 && fullBytes < len(hash) {
			mask := byte(0xFF << (8 - remainder))
			if hash[fullBytes]&mask != 0 {
				valid = false
			}
		}
		if valid {
			log.Printf("✅ Solved KiwiFlare PoW: salt=%s nonce=%d difficulty=%d", trimLong(salt, 16), nonce, diff)
			elapsed := time.Since(start)
			if elapsed < 2*time.Second {
				time.Sleep(2*time.Second - elapsed)
			}
			break
		}
	}

	submit := fmt.Sprintf("https://%s/.sssg/api/answer", crs.domain)
	form := url.Values{"a": {salt}, "b": {fmt.Sprintf("%d", nonce)}}
	req, _ := http.NewRequest("POST", submit, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := crs.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyResp, _ := io.ReadAll(resp.Body)

	var parsed map[string]any
	_ = json.Unmarshal(bodyResp, &parsed)
	if auth, ok := parsed["auth"].(string); ok {
		return auth, nil
	}
	return "", fmt.Errorf("no auth field in KiwiFlare response")
}