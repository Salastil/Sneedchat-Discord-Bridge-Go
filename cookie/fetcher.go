package cookie

import (
	"crypto/sha256"
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 45 * time.Second,
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

	// Step 1: KiwiFlare clearance
	log.Println("Step 1: Checking for KiwiFlare challenge...")
	req, _ := http.NewRequest("GET", baseURL+"/", nil)
	req.Header.Set("User-Agent", randomUserAgent())

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
		return "", fmt.Errorf("missing CSRF token")
	}
	log.Printf("✅ Found CSRF token: %s...", trimLong(csrfToken, 10))

	// Step 4: POST login credentials (full browser headers + both redirect fields)
	loginPost := fmt.Sprintf("%s/login/login", baseURL)
	data := url.Values{
		"_xfToken":    {csrfToken},
		"login":       {crs.username},
		"password":    {crs.password},
		"remember":    {"1"},
		"redirect":    {"/"},
		"_xfRedirect": {baseURL + "/"},
	}

	postReq, _ := http.NewRequest("POST", loginPost, strings.NewReader(data.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", randomUserAgent())
	postReq.Header.Set("Referer", loginURL)
	postReq.Header.Set("Origin", baseURL)
	postReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	postReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
	postReq.Header.Set("Connection", "keep-alive")
	postReq.Header.Set("Upgrade-Insecure-Requests", "1")

	loginResp, err := crs.client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("login POST failed: %w", err)
	}
	defer loginResp.Body.Close()

	log.Printf("Login response status: %d", loginResp.StatusCode)

	// 🧩 Diagnostic: if status 200, dump first KB of body for debugging
	if loginResp.StatusCode == 200 {
		bodyBytes, _ := io.ReadAll(loginResp.Body)
		snippet := string(bodyBytes)
		if len(snippet) > 1000 {
			snippet = snippet[:1000]
		}
		log.Printf("🧩 Login 200 body snippet:\n%s", snippet)
		// Recreate reader for downstream reuse
		loginResp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	time.Sleep(2 * time.Second)

	// Step 5: Check cookies in jar
	cookieURL, _ := url.Parse(baseURL)
	cookies := crs.client.Jar.Cookies(cookieURL)
	hasXfUser := false
	for _, c := range cookies {
		log.Printf("🍪 [After Login POST] %s=%s", c.Name, trimLong(c.Value, 10))
		if c.Name == "xf_user" {
			hasXfUser = true
		}
	}

	// 🔁 Follow redirect manually if missing xf_user
	if !hasXfUser {
		log.Println("🧭 Following post-login redirect manually to capture xf_user...")
		time.Sleep(1 * time.Second)
		followReq, _ := http.NewRequest("GET", baseURL+"/", nil)
		followReq.Header.Set("User-Agent", randomUserAgent())
		followReq.Header.Set("Referer", baseURL+"/login")
		followReq.Header.Set("Origin", baseURL)
		followReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		followReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
		followResp, ferr := crs.client.Do(followReq)
		if ferr != nil {
			log.Printf("⚠️ Redirect follow failed: %v", ferr)
		} else {
			followResp.Body.Close()
			log.Printf("📩 [HTTP GET] %s/ -> %s", baseURL, followResp.Status)
		}
		time.Sleep(1 * time.Second)

		cookies = crs.client.Jar.Cookies(cookieURL)
		for _, c := range cookies {
			log.Printf("🍪 [After Redirect] %s=%s", c.Name, trimLong(c.Value, 10))
			if c.Name == "xf_user" {
				hasXfUser = true
			}
		}
		if hasXfUser {
			log.Println("✅ xf_user cookie acquired after redirect follow")
		} else {
			log.Println("⚠️ xf_user cookie still missing after redirect follow")
		}
	}

	// 🧭 Secondary check — trigger /account/ to issue xf_user if still missing
	if !hasXfUser {
		log.Println("🧭 Performing secondary authenticated fetch to /account/ to trigger xf_user...")
		time.Sleep(1 * time.Second)
		accountReq, _ := http.NewRequest("GET", baseURL+"/account/", nil)
		accountReq.Header.Set("User-Agent", randomUserAgent())
		accountReq.Header.Set("Referer", baseURL+"/login")
		accountReq.Header.Set("Origin", baseURL)
		accountReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		accountReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
		accountResp, accErr := crs.client.Do(accountReq)
		if accErr != nil {
			log.Printf("⚠️ Account fetch failed: %v", accErr)
		} else {
			accountResp.Body.Close()
			log.Printf("📩 [HTTP GET] %s/account/ -> %s", baseURL, accountResp.Status)
		}
		time.Sleep(1 * time.Second)

		cookies = crs.client.Jar.Cookies(cookieURL)
		for _, c := range cookies {
			log.Printf("🍪 [After /account/] %s=%s", c.Name, trimLong(c.Value, 10))
			if c.Name == "xf_user" {
				hasXfUser = true
			}
		}
		if hasXfUser {
			log.Println("✅ xf_user cookie acquired after /account/ fetch")
		} else {
			log.Println("⚠️ xf_user cookie still missing after /account/ fetch")
			return "", fmt.Errorf("xf_user still missing after all follow-ups")
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

func randomUserAgent() string {
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
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

	submit := fmt.Sprintf("%s/.sssg/api/answer", baseURL(crs.domain))
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

func baseURL(domain string) string {
	return fmt.Sprintf("https://%s", domain)
}
