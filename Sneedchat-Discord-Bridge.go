package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// -----------------------------
// Constants
// -----------------------------
const (
	ProcessedCacheSize      = 250
	OutboundMatchWindow     = 60 * time.Second
	CookieRefreshInterval   = 4 * time.Hour
	OutageUpdateInterval    = 10 * time.Second
	QueuedMessageTTL        = 90 * time.Second
	MaxAttachments          = 4
	LitterboxTTL            = "72h"
	MappingCacheSize        = 1000
	MappingCleanupInterval  = 5 * time.Minute
	MappingMaxAge           = 1 * time.Hour
	ReconnectInterval       = 7 * time.Second
	CookieRetryDelay        = 5 * time.Second
	MaxCookieRetryDelay     = 60 * time.Second
)

// -----------------------------
// Configuration
// -----------------------------
type Config struct {
	DiscordBotToken   string
	DiscordChannelID  string
	DiscordGuildID    string
	DiscordWebhookURL string
	SneedchatRoomID   int
	BridgeUsername    string
	BridgePassword    string
	BridgeUserID      int
	DiscordPingUserID string
	Debug             bool
}

func loadConfig(envFile string) (*Config, error) {
	if err := godotenv.Load(envFile); err != nil {
		log.Printf("Warning: Error loading %s file: %v", envFile, err)
	}

	config := &Config{
		DiscordBotToken:   os.Getenv("DISCORD_BOT_TOKEN"),
		DiscordChannelID:  os.Getenv("DISCORD_CHANNEL_ID"),
		DiscordGuildID:    os.Getenv("DISCORD_GUILD_ID"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		BridgeUsername:    os.Getenv("BRIDGE_USERNAME"),
		BridgePassword:    os.Getenv("BRIDGE_PASSWORD"),
	}

	roomID, err := strconv.Atoi(os.Getenv("SNEEDCHAT_ROOM_ID"))
	if err != nil {
		return nil, fmt.Errorf("invalid SNEEDCHAT_ROOM_ID: %w", err)
	}
	config.SneedchatRoomID = roomID

	if bridgeUserID := os.Getenv("BRIDGE_USER_ID"); bridgeUserID != "" {
		config.BridgeUserID, _ = strconv.Atoi(bridgeUserID)
	}

	config.DiscordPingUserID = os.Getenv("DISCORD_PING_USER_ID")

	return config, nil
}

// -----------------------------
// BBCode to Markdown Parser
// -----------------------------
func bbcodeToMarkdown(text string) string {
	if text == "" {
		return ""
	}

	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// Images & videos
	text = regexp.MustCompile(`(?i)\[img\](.*?)\[/img\]`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`(?i)\[video\](.*?)\[/video\]`).ReplaceAllString(text, "$1")

	// URL with text
	urlPattern := regexp.MustCompile(`(?i)\[url=(.*?)\](.*?)\[/url\]`)
	text = urlPattern.ReplaceAllStringFunc(text, func(match string) string {
		parts := urlPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		link := strings.TrimSpace(parts[1])
		txt := strings.TrimSpace(parts[2])
		if regexp.MustCompile(`(?i)^https?://`).MatchString(txt) {
			return txt
		}
		return fmt.Sprintf("[%s](%s)", txt, link)
	})

	// URL without text
	text = regexp.MustCompile(`(?i)\[url\](.*?)\[/url\]`).ReplaceAllString(text, "$1")

	// Bold, italic, underline, strike
	text = regexp.MustCompile(`(?i)\[(?:b|strong)\](.*?)\[/\s*(?:b|strong)\]`).ReplaceAllString(text, "**$1**")
	text = regexp.MustCompile(`(?i)\[(?:i|em)\](.*?)\[/\s*(?:i|em)\]`).ReplaceAllString(text, "*$1*")
	text = regexp.MustCompile(`(?i)\[u\](.*?)\[/\s*u\]`).ReplaceAllString(text, "__$1__")
	text = regexp.MustCompile(`(?i)\[(?:s|strike)\](.*?)\[/\s*(?:s|strike)\]`).ReplaceAllString(text, "~~$1~~")

	// Code
	text = regexp.MustCompile(`(?i)\[code\](.*?)\[/code\]`).ReplaceAllString(text, "`$1`")
	text = regexp.MustCompile(`(?i)\[(?:php|plain|code=\w+)\](.*?)\[/(?:php|plain|code)\]`).ReplaceAllString(text, "```$1```")

	// Quotes (basic implementation)
	quotePattern := regexp.MustCompile(`(?i)\[quote\](.*?)\[/quote\]`)
	text = quotePattern.ReplaceAllStringFunc(text, func(match string) string {
		parts := quotePattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		inner := strings.TrimSpace(parts[1])
		lines := strings.Split(inner, "\n")
		for i, line := range lines {
			lines[i] = "> " + line
		}
		return strings.Join(lines, "\n")
	})

	// Spoilers
	text = regexp.MustCompile(`(?i)\[spoiler\](.*?)\[/spoiler\]`).ReplaceAllString(text, "||$1||")

	// Color/size - strip but keep content
	text = regexp.MustCompile(`(?i)\[(?:color|size)=.*?\](.*?)\[/\s*(?:color|size)\]`).ReplaceAllString(text, "$1")

	// Lists
	text = regexp.MustCompile(`(?m)^\[\*\]\s*`).ReplaceAllString(text, "• ")
	text = regexp.MustCompile(`(?i)\[/?list\]`).ReplaceAllString(text, "")

	// Remove unknown tags
	text = regexp.MustCompile(`\[/?[A-Za-z0-9\-=_]+\]`).ReplaceAllString(text, "")

	return strings.TrimSpace(text)
}

// -----------------------------
// Bounded Map (Memory Management)
// -----------------------------
type BoundedMap struct {
	mu         sync.RWMutex
	data       map[int]interface{}
	timestamps map[int]time.Time
	maxSize    int
	maxAge     time.Duration
	keys       []int // Track insertion order for LRU
}

func NewBoundedMap(maxSize int, maxAge time.Duration) *BoundedMap {
	return &BoundedMap{
		data:       make(map[int]interface{}),
		timestamps: make(map[int]time.Time),
		maxSize:    maxSize,
		maxAge:     maxAge,
		keys:       make([]int, 0, maxSize),
	}
}

func (bm *BoundedMap) Set(key int, value interface{}) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// If key exists, update and move to end
	if _, exists := bm.data[key]; exists {
		bm.data[key] = value
		bm.timestamps[key] = time.Now()
		// Move to end
		for i, k := range bm.keys {
			if k == key {
				bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
				break
			}
		}
		bm.keys = append(bm.keys, key)
		return
	}

	// New entry
	bm.data[key] = value
	bm.timestamps[key] = time.Now()
	bm.keys = append(bm.keys, key)

	// Evict oldest if over capacity
	if len(bm.data) > bm.maxSize {
		oldest := bm.keys[0]
		delete(bm.data, oldest)
		delete(bm.timestamps, oldest)
		bm.keys = bm.keys[1:]
	}
}

func (bm *BoundedMap) Get(key int) (interface{}, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	val, exists := bm.data[key]
	return val, exists
}

func (bm *BoundedMap) Delete(key int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.data, key)
	delete(bm.timestamps, key)
	for i, k := range bm.keys {
		if k == key {
			bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
			break
		}
	}
}

func (bm *BoundedMap) CleanupOldEntries() int {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, ts := range bm.timestamps {
		if now.Sub(ts) > bm.maxAge {
			delete(bm.data, key)
			delete(bm.timestamps, key)
			for i, k := range bm.keys {
				if k == key {
					bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
					break
				}
			}
			removed++
		}
	}

	return removed
}

func (bm *BoundedMap) Len() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.data)
}

// -----------------------------
// Cookie Refresh Service
// -----------------------------
type CookieRefreshService struct {
	username       string
	password       string
	domain         string
	client         *http.Client
	currentCookie  string
	cookieMu       sync.RWMutex
	cookieReady    chan struct{}
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

func NewCookieRefreshService(username, password, domain string) (*CookieRefreshService, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &CookieRefreshService{
		username:    username,
		password:    password,
		domain:      domain,
		client:      &http.Client{Jar: jar, Timeout: 30 * time.Second},
		cookieReady: make(chan struct{}),
		stopChan:    make(chan struct{}),
	}, nil
}

func (crs *CookieRefreshService) getClearanceToken() (string, error) {
	baseURL := fmt.Sprintf("https://%s/", crs.domain)
	resp, err := crs.client.Get(baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Try multiple patterns for KiwiFlare challenge detection
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<html[^>]*id=["']sssg["'][^>]*data-sssg-challenge=["']([^"']+)["'][^>]*data-sssg-difficulty=["'](\d+)["']`),
		regexp.MustCompile(`<html[^>]*id=["']sssg["'][^>]*data-sssg-difficulty=["'](\d+)["'][^>]*data-sssg-challenge=["']([^"']+)["']`),
		regexp.MustCompile(`data-sssg-challenge=["']([^"']+)["'][^>]*data-sssg-difficulty=["'](\d+)["']`),
	}

	var salt string
	var difficulty int
	found := false

	for i, pattern := range patterns {
		matches := pattern.FindStringSubmatch(string(body))
		if len(matches) >= 3 {
			if i == 1 {
				// Pattern has difficulty first, then challenge
				difficulty, _ = strconv.Atoi(matches[1])
				salt = matches[2]
			} else {
				salt = matches[1]
				difficulty, _ = strconv.Atoi(matches[2])
			}
			found = true
			break
		}
	}

	if !found {
		log.Println("No KiwiFlare challenge required")
		return "", nil
	}

	if difficulty == 0 {
		return "", nil
	}

	log.Printf("Solving KiwiFlare challenge (difficulty=%d)", difficulty)

	nonce, err := crs.solvePoW(salt, difficulty)
	if err != nil {
		return "", err
	}

	submitURL := fmt.Sprintf("https://%s/.sssg/api/answer", crs.domain)
	formData := url.Values{"a": {salt}, "b": {nonce}}

	submitResp, err := crs.client.PostForm(submitURL, formData)
	if err != nil {
		return "", err
	}
	defer submitResp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(submitResp.Body).Decode(&result); err != nil {
		return "", err
	}

	if auth, ok := result["auth"].(string); ok {
		// Manually add the clearance cookie to the jar
		cookieURL, _ := url.Parse(baseURL)
		clearanceCookie := &http.Cookie{
			Name:   "sssg_clearance",
			Value:  auth,
			Path:   "/",
			Domain: crs.domain,
		}
		crs.client.Jar.SetCookies(cookieURL, []*http.Cookie{clearanceCookie})
		log.Println("✅ KiwiFlare clearance cookie set")
		return auth, nil
	}

	return "", fmt.Errorf("no auth token in response")
}

func (crs *CookieRefreshService) solvePoW(salt string, difficulty int) (string, error) {
	nonce := rand.Int63()
	requiredBytes := difficulty / 8
	requiredBits := difficulty % 8
	maxAttempts := 10_000_000

	for attempts := 0; attempts < maxAttempts; attempts++ {
		nonce++

		input := fmt.Sprintf("%s%d", salt, nonce)
		hash := sha256.Sum256([]byte(input))

		valid := true
		for i := 0; i < requiredBytes; i++ {
			if hash[i] != 0 {
				valid = false
				break
			}
		}

		if valid && requiredBits > 0 && requiredBytes < len(hash) {
			mask := byte(0xFF << (8 - requiredBits))
			if hash[requiredBytes]&mask != 0 {
				valid = false
			}
		}

		if valid {
			return fmt.Sprintf("%d", nonce), nil
		}
	}

	return "", fmt.Errorf("failed to solve PoW within %d attempts", maxAttempts)
}

func (crs *CookieRefreshService) FetchFreshCookie() (string, error) {
	attempt := 0
	retryDelay := CookieRetryDelay

	for {
		attempt++
		
		if attempt > 1 {
			log.Printf("🔄 Cookie fetch retry attempt %d (waiting %v)...", attempt, retryDelay)
			time.Sleep(retryDelay)
			
			// Exponential backoff with cap
			retryDelay *= 2
			if retryDelay > MaxCookieRetryDelay {
				retryDelay = MaxCookieRetryDelay
			}
		}

		cookie, err := crs.attemptFetchCookie()
		if err != nil {
			log.Printf("⚠️ Cookie fetch attempt %d failed: %v", attempt, err)
			continue
		}

		// Verify xf_user cookie is present
		if strings.Contains(cookie, "xf_user=") {
			log.Printf("✅ Successfully fetched fresh cookie with xf_user (attempt %d)", attempt)
			return cookie, nil
		}

		log.Printf("❌ Cookie fetch attempt %d missing xf_user - login failed, retrying...", attempt)
	}
}

func (crs *CookieRefreshService) attemptFetchCookie() (string, error) {
	// Always start with a fresh cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	crs.client.Jar = jar

	log.Println("Step 1: Checking for KiwiFlare challenge...")

	clearanceToken, err := crs.getClearanceToken()
	if err != nil {
		return "", fmt.Errorf("clearance token error: %w", err)
	}
	if clearanceToken != "" {
		log.Println("✅ KiwiFlare challenge solved")
		time.Sleep(1 * time.Second) // allow propagation
	}

	// Force a new TLS session to avoid stale keep-alive
	crs.client.Transport = &http.Transport{}

	// Step 2: Fetch login page
	log.Println("Step 2: Fetching login page...")
	loginURL := fmt.Sprintf("https://%s/login", crs.domain)
	req, _ := http.NewRequest("GET", loginURL, nil)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.URL.RawQuery = fmt.Sprintf("r=%d", rand.Intn(999999))

	resp, err := crs.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get login page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login page returned HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Step 3: Extract CSRF token
	log.Println("Step 3: Extracting CSRF token...")
	var csrfToken string
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`<html[^>]*data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`data-csrf=["']([^"']+)["']`),
		regexp.MustCompile(`"csrf":"([^"]+)"`),
		regexp.MustCompile(`XF\.config\.csrf\s*=\s*"([^"]+)"`),
	} {
		if m := pattern.FindStringSubmatch(bodyStr); len(m) >= 2 {
			csrfToken = m[1]
			break
		}
	}

	if csrfToken == "" {
		log.Printf("⚠️ CSRF token not found. Partial HTML:\n%s", bodyStr[:min(800, len(bodyStr))])
		return "", fmt.Errorf("CSRF token not found in login page")
	}
	log.Printf("✅ Found CSRF token: %s...", csrfToken[:min(10, len(csrfToken))])

	// Step 4: Submit login credentials
	log.Println("Step 4: Submitting login credentials...")
	postURL := fmt.Sprintf("https://%s/login/login", crs.domain)
	formData := url.Values{
		"_xfToken":    {csrfToken},
		"login":       {crs.username},
		"password":    {crs.password},
		"_xfRedirect": {fmt.Sprintf("https://%s/", crs.domain)},
		"remember":    {"1"},
	}

	crs.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginResp, err := crs.client.PostForm(postURL, formData)
	if err != nil {
		return "", fmt.Errorf("login POST failed: %w", err)
	}
	defer loginResp.Body.Close()

	log.Printf("Login response status: %d", loginResp.StatusCode)

	// Step 5: Extract cookies
	log.Println("Step 5: Extracting authentication cookies...")
	cookieURL, _ := url.Parse(fmt.Sprintf("https://%s/", crs.domain))
	cookies := crs.client.Jar.Cookies(cookieURL)

	wanted := map[string]bool{
		"xf_user":        true,
		"xf_toggle":      true,
		"xf_csrf":        true,
		"xf_session":     true,
		"sssg_clearance": true,
	}

	var cookieStrs []string
	hasXfUser := false
	for _, c := range cookies {
		if wanted[c.Name] {
			cookieStrs = append(cookieStrs, fmt.Sprintf("%s=%s", c.Name, c.Value))
			if c.Name == "xf_user" {
				hasXfUser = true
			}
		}
	}

	// Try manual redirect follow if still missing xf_user
	if !hasXfUser && loginResp.StatusCode >= 300 && loginResp.StatusCode < 400 {
		if loc := loginResp.Header.Get("Location"); loc != "" {
			log.Printf("Following redirect to %s to check for xf_user...", loc)
			followResp, err := crs.client.Get(fmt.Sprintf("https://%s%s", crs.domain, loc))
			if err == nil {
				followResp.Body.Close()
				cookies = crs.client.Jar.Cookies(cookieURL)
				cookieStrs = []string{} // Reset
				for _, c := range cookies {
					if wanted[c.Name] {
						cookieStrs = append(cookieStrs, fmt.Sprintf("%s=%s", c.Name, c.Value))
						if c.Name == "xf_user" {
							hasXfUser = true
						}
					}
				}
			}
		}
	}

	if !hasXfUser {
		// ❌ Return error (so FetchFreshCookie retries indefinitely)
		return "", fmt.Errorf("xf_user cookie missing — authentication failed, will retry")
	}

	cookieString := strings.Join(cookieStrs, "; ")
	log.Printf("✅ Successfully fetched fresh cookie with xf_user")
	return cookieString, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (crs *CookieRefreshService) Start() {
	crs.wg.Add(1)
	go crs.refreshLoop()
}

func (crs *CookieRefreshService) refreshLoop() {
	defer crs.wg.Done()

	log.Println("🔑 Fetching initial cookie...")
	freshCookie, err := crs.FetchFreshCookie()
	if err != nil {
		log.Printf("❌ Failed to acquire initial cookie: %v", err)
		return
	}

	crs.cookieMu.Lock()
	crs.currentCookie = freshCookie
	crs.cookieMu.Unlock()
	close(crs.cookieReady)
	log.Println("✅ Initial cookie acquired")

	ticker := time.NewTicker(CookieRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("🔄 Starting automatic cookie refresh")
			freshCookie, err := crs.FetchFreshCookie()
			if err != nil {
				log.Printf("⚠️ Cookie refresh failed: %v", err)
			} else {
				crs.cookieMu.Lock()
				crs.currentCookie = freshCookie
				crs.cookieMu.Unlock()
				log.Println("✅ Cookie refresh completed")
			}
		case <-crs.stopChan:
			return
		}
	}
}

func (crs *CookieRefreshService) WaitForCookie() {
	<-crs.cookieReady
}

func (crs *CookieRefreshService) GetCurrentCookie() string {
	crs.cookieMu.RLock()
	defer crs.cookieMu.RUnlock()
	return crs.currentCookie
}

func (crs *CookieRefreshService) Stop() {
	close(crs.stopChan)
	crs.wg.Wait()
}

// -----------------------------
// Sneedchat Message Types
// -----------------------------
type SneedMessage struct {
	MessageID      int                    `json:"message_id"`
	Message        string                 `json:"message"`
	MessageRaw     string                 `json:"message_raw"`
	MessageEditDate int                   `json:"message_edit_date"`
	Author         map[string]interface{} `json:"author"`
	Deleted        bool                   `json:"deleted"`
	IsDeleted      bool                   `json:"is_deleted"`
}

type SneedPayload struct {
	Messages []SneedMessage         `json:"messages"`
	Message  *SneedMessage          `json:"message"`
	Delete   interface{}            `json:"delete"`
}

// -----------------------------
// Sneedchat Client
// -----------------------------
type SneedChatClient struct {
	wsURL              string
	cookie             string
	cookieService      *CookieRefreshService
	roomID             int
	conn               *websocket.Conn
	connected          bool
	connMu             sync.RWMutex
	writeQueue         chan string
	stopChan           chan struct{}
	wg                 sync.WaitGroup
	reconnectAttempts  int
	reconnectInterval  time.Duration
	lastMessageTime    time.Time
	
	processedMessageIDs []int
	messageEditDates    *BoundedMap
	processedMu         sync.Mutex

	onMessage    func(map[string]interface{})
	onEdit       func(int, string)
	onDelete     func(int)
	onConnect    func()
	onDisconnect func()

	recentOutboundIter func() []map[string]interface{}
	mapDiscordSneed    func(int, int, string)
}

func NewSneedChatClient(cookie string, roomID int, cookieService *CookieRefreshService) *SneedChatClient {
	return &SneedChatClient{
		wsURL:              "wss://kiwifarms.st:9443/chat.ws",
		cookie:             cookie,
		cookieService:      cookieService,
		roomID:             roomID,
		writeQueue:         make(chan string, 100),
		stopChan:           make(chan struct{}),
		reconnectInterval:  ReconnectInterval,
		processedMessageIDs: make([]int, 0, ProcessedCacheSize),
		messageEditDates:   NewBoundedMap(MappingCacheSize, MappingMaxAge),
		lastMessageTime:    time.Now(),
	}
}

func (sc *SneedChatClient) Connect() error {
	sc.connMu.Lock()
	if sc.connected {
		sc.connMu.Unlock()
		return nil
	}
	sc.connMu.Unlock()

	// Refresh cookie if available
	if sc.cookieService != nil {
		freshCookie := sc.cookieService.GetCurrentCookie()
		if freshCookie != "" {
			sc.cookie = freshCookie
		}
	}

	headers := http.Header{}
	headers.Add("Cookie", sc.cookie)

	log.Printf("Connecting to Sneedchat room %d", sc.roomID)
	conn, _, err := websocket.DefaultDialer.Dial(sc.wsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket connection failed: %w", err)
	}

	sc.connMu.Lock()
	sc.conn = conn
	sc.connected = true
	sc.reconnectAttempts = 0
	sc.connMu.Unlock()

	// Start goroutines
	sc.wg.Add(4)
	go sc.readLoop()
	go sc.writeLoop()
	go sc.heartbeatLoop()
	go sc.cleanupLoop()

	// Join room
	sc.SendCommand(fmt.Sprintf("/join %d", sc.roomID))

	log.Printf("✅ Successfully connected to Sneedchat room %d", sc.roomID)
	if sc.onConnect != nil {
		sc.onConnect()
	}

	return nil
}

func (sc *SneedChatClient) Disconnect() {
	log.Println("Disconnecting from Sneedchat")
	
	sc.connMu.Lock()
	sc.connected = false
	if sc.conn != nil {
		sc.conn.Close()
	}
	sc.connMu.Unlock()

	close(sc.stopChan)
	sc.wg.Wait()
}

func (sc *SneedChatClient) readLoop() {
	defer sc.wg.Done()
	defer sc.handleDisconnect()

	for {
		select {
		case <-sc.stopChan:
			return
		default:
		}

		sc.connMu.RLock()
		conn := sc.conn
		sc.connMu.RUnlock()

		if conn == nil {
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Sneedchat read error: %v", err)
			return
		}

		sc.lastMessageTime = time.Now()
		sc.handleMessage(string(message))
	}
}

func (sc *SneedChatClient) writeLoop() {
	defer sc.wg.Done()

	for {
		select {
		case msg := <-sc.writeQueue:
			sc.connMu.RLock()
			conn := sc.conn
			connected := sc.connected
			sc.connMu.RUnlock()

			if !connected || conn == nil {
				continue
			}

			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				log.Printf("Sneedchat write error: %v", err)
				return
			}

		case <-sc.stopChan:
			return
		}
	}
}

func (sc *SneedChatClient) heartbeatLoop() {
	defer sc.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sc.connMu.RLock()
			connected := sc.connected
			sc.connMu.RUnlock()

			if connected && time.Since(sc.lastMessageTime) > 60*time.Second {
				sc.SendCommand("/ping")
			}

		case <-sc.stopChan:
			return
		}
	}
}

func (sc *SneedChatClient) cleanupLoop() {
	defer sc.wg.Done()

	ticker := time.NewTicker(MappingCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := sc.messageEditDates.CleanupOldEntries()
			if removed > 0 {
				log.Printf("🧹 Cleaned up %d old message edit tracking entries", removed)
			}

		case <-sc.stopChan:
			return
		}
	}
}

func (sc *SneedChatClient) handleMessage(raw string) {
	var payload SneedPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return
	}

	// Handle top-level deletes
	if payload.Delete != nil {
		var deleteIDs []int
		switch v := payload.Delete.(type) {
		case float64:
			deleteIDs = []int{int(v)}
		case []interface{}:
			for _, id := range v {
				if fid, ok := id.(float64); ok {
					deleteIDs = append(deleteIDs, int(fid))
				}
			}
		}

		for _, did := range deleteIDs {
			log.Printf("🗑️ Received top-level Sneed delete for id=%d", did)
			sc.messageEditDates.Delete(did)
			sc.removeFromProcessed(did)
			if sc.onDelete != nil {
				sc.onDelete(did)
			}
		}
	}

	// Collect messages
	var messages []SneedMessage
	if len(payload.Messages) > 0 {
		messages = payload.Messages
	} else if payload.Message != nil {
		messages = []SneedMessage{*payload.Message}
	}

	for _, msg := range messages {
		sc.processMessage(msg)
	}
}

func (sc *SneedChatClient) processMessage(msg SneedMessage) {
	username := "Unknown"
	var userID int
	if author, ok := msg.Author["username"].(string); ok {
		username = author
	}
	if id, ok := msg.Author["id"].(float64); ok {
		userID = int(id)
	}

	messageText := msg.MessageRaw
	if messageText == "" {
		messageText = msg.Message
	}
	messageText = html.UnescapeString(messageText)

	editDate := msg.MessageEditDate
	deleted := msg.Deleted || msg.IsDeleted

	// Message-scoped deletion
	if deleted {
		log.Printf("🗑️ Sneed message-scoped deletion id=%d", msg.MessageID)
		sc.messageEditDates.Delete(msg.MessageID)
		sc.removeFromProcessed(msg.MessageID)
		if sc.onDelete != nil {
			sc.onDelete(msg.MessageID)
		}
		return
	}

	// Skip bridge user echoes
	bridgeUserID, _ := strconv.Atoi(os.Getenv("BRIDGE_USER_ID"))
	bridgeUsername := os.Getenv("BRIDGE_USERNAME")
	
	if (bridgeUserID > 0 && userID == bridgeUserID) || (bridgeUsername != "" && username == bridgeUsername) {
		log.Printf("🚫 Received bridge-user echo from Sneed id=%d", msg.MessageID)
		
		// Attempt mapping
		if msg.MessageID > 0 && sc.recentOutboundIter != nil && sc.mapDiscordSneed != nil {
			now := time.Now()
			for _, entry := range sc.recentOutboundIter() {
				if mapped, ok := entry["mapped"].(bool); ok && mapped {
					continue
				}
				if content, ok := entry["content"].(string); ok {
					if ts, ok := entry["ts"].(time.Time); ok {
						if content == messageText && now.Sub(ts) <= OutboundMatchWindow {
							if discordID, ok := entry["discord_id"].(int); ok {
								sc.mapDiscordSneed(discordID, msg.MessageID, username)
								entry["mapped"] = true
								break
							}
						}
					}
				}
			}
		}

		sc.addToProcessed(msg.MessageID)
		sc.messageEditDates.Set(msg.MessageID, editDate)
		return
	}

	// Dedup / edit detection
	if sc.isProcessed(msg.MessageID) {
		if prevEdit, exists := sc.messageEditDates.Get(msg.MessageID); exists {
			prevEditInt := prevEdit.(int)
			if editDate > prevEditInt {
				log.Printf("✏️ Edit detected for sneed_id=%d", msg.MessageID)
				sc.messageEditDates.Set(msg.MessageID, editDate)
				if sc.onEdit != nil {
					sc.onEdit(msg.MessageID, messageText)
				}
			}
		}
		return
	}

	// New message
	log.Printf("📄 New Sneed message from %s", username)
	sc.addToProcessed(msg.MessageID)
	sc.messageEditDates.Set(msg.MessageID, editDate)

	if sc.onMessage != nil {
		sc.onMessage(map[string]interface{}{
			"username":  username,
			"content":   messageText,
			"raw":       msg,
			"message_id": msg.MessageID,
			"author_id":  userID,
		})
	}
}

func (sc *SneedChatClient) isProcessed(id int) bool {
	sc.processedMu.Lock()
	defer sc.processedMu.Unlock()
	for _, pid := range sc.processedMessageIDs {
		if pid == id {
			return true
		}
	}
	return false
}

func (sc *SneedChatClient) addToProcessed(id int) {
	sc.processedMu.Lock()
	defer sc.processedMu.Unlock()
	sc.processedMessageIDs = append(sc.processedMessageIDs, id)
	if len(sc.processedMessageIDs) > ProcessedCacheSize {
		sc.processedMessageIDs = sc.processedMessageIDs[1:]
	}
}

func (sc *SneedChatClient) removeFromProcessed(id int) {
	sc.processedMu.Lock()
	defer sc.processedMu.Unlock()
	for i, pid := range sc.processedMessageIDs {
		if pid == id {
			sc.processedMessageIDs = append(sc.processedMessageIDs[:i], sc.processedMessageIDs[i+1:]...)
			return
		}
	}
}

func (sc *SneedChatClient) SendMessage(content string) bool {
	sc.connMu.RLock()
	connected := sc.connected
	sc.connMu.RUnlock()

	if !connected {
		log.Println("Cannot send to Sneedchat: not connected")
		return false
	}

	select {
	case sc.writeQueue <- content:
		return true
	default:
		log.Println("Write queue full")
		return false
	}
}

func (sc *SneedChatClient) SendCommand(command string) {
	sc.connMu.RLock()
	connected := sc.connected
	sc.connMu.RUnlock()

	if !connected {
		return
	}

	select {
	case sc.writeQueue <- command:
	default:
	}
}

func (sc *SneedChatClient) handleDisconnect() {
	select {
	case <-sc.stopChan:
		return
	default:
	}

	sc.reconnectAttempts++
	sc.connMu.Lock()
	sc.connected = false
	sc.connMu.Unlock()

	log.Println("🔴 Sneedchat disconnected")
	if sc.onDisconnect != nil {
		sc.onDisconnect()
	}

	time.Sleep(sc.reconnectInterval)
	sc.Connect()
}

// -----------------------------
// Discord Bridge
// -----------------------------
type OutboundEntry struct {
	DiscordID int
	Content   string
	Timestamp time.Time
	Mapped    bool
}

type QueuedMessage struct {
	Content   string
	ChannelID string
	Timestamp time.Time
	DiscordID int
}

type DiscordBridge struct {
	config        *Config
	session       *discordgo.Session
	sneedClient   *SneedChatClient
	httpClient    *http.Client

	sneedToDiscord *BoundedMap
	discordToSneed *BoundedMap
	sneedUsernames *BoundedMap

	recentOutbound    []OutboundEntry
	recentOutboundMu  sync.Mutex

	queuedOutbound   []QueuedMessage
	queuedOutboundMu sync.Mutex

	outageMessages    []*discordgo.Message // Track all outage messages for cleanup
	outageMessagesMu  sync.Mutex
	outageStart       time.Time
	outageMu          sync.Mutex

	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewDiscordBridge(config *Config, sneedClient *SneedChatClient) (*DiscordBridge, error) {
	session, err := discordgo.New("Bot " + config.DiscordBotToken)
	if err != nil {
		return nil, err
	}

	bridge := &DiscordBridge{
		config:         config,
		session:        session,
		sneedClient:    sneedClient,
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		sneedToDiscord: NewBoundedMap(MappingCacheSize, MappingMaxAge),
		discordToSneed: NewBoundedMap(MappingCacheSize, MappingMaxAge),
		sneedUsernames: NewBoundedMap(MappingCacheSize, MappingMaxAge),
		recentOutbound: make([]OutboundEntry, 0, ProcessedCacheSize),
		queuedOutbound: make([]QueuedMessage, 0),
		outageMessages: make([]*discordgo.Message, 0),
		stopChan:       make(chan struct{}),
	}

	// Set up callbacks
	sneedClient.onMessage = bridge.onSneedMessage
	sneedClient.onEdit = bridge.handleSneedEdit
	sneedClient.onDelete = bridge.handleSneedDelete
	sneedClient.onConnect = bridge.onSneedConnect
	sneedClient.onDisconnect = bridge.onSneedDisconnect

	sneedClient.recentOutboundIter = bridge.recentOutboundIter
	sneedClient.mapDiscordSneed = bridge.mapDiscordSneed

	// Set up Discord handlers
	session.AddHandler(bridge.onDiscordReady)
	session.AddHandler(bridge.onDiscordMessage)
	session.AddHandler(bridge.onDiscordMessageEdit)
	session.AddHandler(bridge.onDiscordMessageDelete)

	return bridge, nil
}

func (db *DiscordBridge) Start() error {
	db.session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent

	if err := db.session.Open(); err != nil {
		return err
	}

	db.wg.Add(1)
	go db.cleanupLoop()

	return nil
}

func (db *DiscordBridge) Stop() {
	close(db.stopChan)
	db.session.Close()
	db.wg.Wait()
}

func (db *DiscordBridge) cleanupLoop() {
	defer db.wg.Done()

	ticker := time.NewTicker(MappingCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := 0
			removed += db.sneedToDiscord.CleanupOldEntries()
			removed += db.discordToSneed.CleanupOldEntries()
			removed += db.sneedUsernames.CleanupOldEntries()

			if removed > 0 {
				log.Printf("🧹 Cleaned up %d old message mappings", removed)
			}

			// Cleanup expired queued messages
			db.queuedOutboundMu.Lock()
			now := time.Now()
			before := len(db.queuedOutbound)
			filtered := make([]QueuedMessage, 0)
			for _, msg := range db.queuedOutbound {
				if now.Sub(msg.Timestamp) <= QueuedMessageTTL {
					filtered = append(filtered, msg)
				}
			}
			db.queuedOutbound = filtered
			after := len(db.queuedOutbound)
			db.queuedOutboundMu.Unlock()

			if before > after {
				log.Printf("🧹 Removed %d expired queued messages", before-after)
			}

		case <-db.stopChan:
			return
		}
	}
}

func (db *DiscordBridge) onDiscordReady(s *discordgo.Session, event *discordgo.Ready) {
	log.Printf("🤖 Discord bot ready: %s (id=%s)", event.User.Username, event.User.ID)

	if !db.sneedClient.connected {
		go db.sneedClient.Connect()
	}
}

func (db *DiscordBridge) onDiscordMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.Bot {
		return
	}

	if m.ChannelID != db.config.DiscordChannelID {
		return
	}

	// Handle commands
	if strings.HasPrefix(m.Content, "!status") {
		db.handleStatusCommand(s, m)
		return
	}

	if strings.HasPrefix(m.Content, "!test") {
		db.handleTestCommand(s, m)
		return
	}

	log.Printf("📤 Discord → Sneedchat: %s: %s", m.Author.Username, m.Content)
	db.handleDiscordMessage(m)
}

func (db *DiscordBridge) handleStatusCommand(s *discordgo.Session, m *discordgo.MessageCreate) {
	status := "🟢 Connected"
	color := 0x00FF00
	if !db.sneedClient.connected {
		status = "🔴 Disconnected"
		color = 0xFF0000
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🌉 Bridge Status",
		Description: fmt.Sprintf("**Sneedchat:** %s\n**Room ID:** %d", status, db.sneedClient.roomID),
		Color:       color,
	}

	s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func (db *DiscordBridge) handleTestCommand(s *discordgo.Session, m *discordgo.MessageCreate) {
	text := "This is a test from !test"
	if len(m.Content) > 6 {
		text = strings.TrimSpace(m.Content[6:])
	}

	webhookID, webhookToken := parseWebhookURL(db.config.DiscordWebhookURL)
	params := &discordgo.WebhookParams{
		Content:  text,
		Username: "SneedTestUser",
	}

	_, err := s.WebhookExecute(webhookID, webhookToken, true, params)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Failed: %v", err))
		return
	}

	s.ChannelMessageSend(m.ChannelID, "✅ Test message sent via webhook.")
}

func (db *DiscordBridge) handleDiscordMessage(m *discordgo.MessageCreate) {
	contentText := strings.TrimSpace(m.Content)

	// Handle reply mapping
	if m.ReferencedMessage != nil {
		refDiscordID := m.ReferencedMessage.ID
		if sneedIDInt, exists := db.discordToSneed.Get(parseMessageID(refDiscordID)); exists {
			if username, exists := db.sneedUsernames.Get(sneedIDInt.(int)); exists {
				contentText = fmt.Sprintf("@%s, %s", username.(string), contentText)
			}
		}
	}

	// Handle attachments
	var attachmentsBB []string
	if len(m.Attachments) > MaxAttachments {
		db.session.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Refusing to upload attachments: limit is %d.", MaxAttachments))
		return
	}

	for _, att := range m.Attachments {
		catboxURL, err := db.uploadToLitterbox(att.URL, att.Filename)
		if err != nil {
			db.session.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Failed to upload attachment `%s` to Litterbox; aborting send.", att.Filename))
			log.Printf("Attachment upload failed for %s: %v", att.Filename, err)
			return
		}

		contentType := strings.ToLower(att.ContentType)
		if strings.HasPrefix(contentType, "video") || strings.HasSuffix(strings.ToLower(att.Filename), ".mp4") ||
			strings.HasSuffix(strings.ToLower(att.Filename), ".webm") {
			attachmentsBB = append(attachmentsBB, fmt.Sprintf("[url=%s][video]%s[/video][/url]", catboxURL, catboxURL))
		} else {
			attachmentsBB = append(attachmentsBB, fmt.Sprintf("[url=%s][img]%s[/img][/url]", catboxURL, catboxURL))
		}
	}

	combined := contentText
	if len(attachmentsBB) > 0 {
		if combined != "" {
			combined += "\n"
		}
		combined += strings.Join(attachmentsBB, "\n")
	}

	// Try to send
	sent := db.sneedClient.SendMessage(combined)
	if sent {
		db.recentOutboundMu.Lock()
		entry := OutboundEntry{
			DiscordID: parseMessageID(m.ID),
			Content:   combined,
			Timestamp: time.Now(),
			Mapped:    false,
		}
		db.recentOutbound = append(db.recentOutbound, entry)
		if len(db.recentOutbound) > ProcessedCacheSize {
			db.recentOutbound = db.recentOutbound[1:]
		}
		db.recentOutboundMu.Unlock()
	} else {
		// Queue message
		db.queuedOutboundMu.Lock()
		db.queuedOutbound = append(db.queuedOutbound, QueuedMessage{
			Content:   combined,
			ChannelID: m.ChannelID,
			Timestamp: time.Now(),
			DiscordID: parseMessageID(m.ID),
		})
		db.queuedOutboundMu.Unlock()

		db.session.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⚠️ Sneedchat appears offline. Your message has been queued for delivery (will expire after %ds).", int(QueuedMessageTTL.Seconds())))
	}
}

func (db *DiscordBridge) uploadToLitterbox(fileURL, filename string) (string, error) {
	// Download from Discord CDN
	resp, err := db.httpClient.Get(fileURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Upload to Litterbox
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("reqtype", "fileupload")
	writer.WriteField("time", LitterboxTTL)

	part, err := writer.CreateFormFile("fileToUpload", filename)
	if err != nil {
		return "", err
	}
	part.Write(data)
	writer.Close()

	req, err := http.NewRequest("POST", "https://litterbox.catbox.moe/resources/internals/api.php", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	uploadResp, err := db.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer uploadResp.Body.Close()

	if uploadResp.StatusCode != 200 {
		return "", fmt.Errorf("Litterbox returned HTTP %d", uploadResp.StatusCode)
	}

	urlBytes, err := io.ReadAll(uploadResp.Body)
	if err != nil {
		return "", err
	}

	url := strings.TrimSpace(string(urlBytes))
	log.Printf("SUCCESS: Uploaded '%s' to Litterbox: %s", filename, url)
	return url, nil
}

func (db *DiscordBridge) onDiscordMessageEdit(s *discordgo.Session, m *discordgo.MessageUpdate) {
	if m.Author == nil || m.Author.Bot {
		return
	}

	discordID := parseMessageID(m.ID)
	sneedIDInt, exists := db.discordToSneed.Get(discordID)
	if !exists {
		return
	}

	sneedID := sneedIDInt.(int)
	payload := map[string]interface{}{
		"id":      sneedID,
		"message": strings.TrimSpace(m.Content),
	}

	payloadJSON, _ := json.Marshal(payload)
	log.Printf("↩️ Discord edit -> Sneedchat (sneed_id=%d)", sneedID)
	db.sneedClient.SendCommand(fmt.Sprintf("/edit %s", string(payloadJSON)))
}

func (db *DiscordBridge) onDiscordMessageDelete(s *discordgo.Session, m *discordgo.MessageDelete) {
	discordID := parseMessageID(m.ID)
	sneedIDInt, exists := db.discordToSneed.Get(discordID)
	if !exists {
		return
	}

	sneedID := sneedIDInt.(int)
	log.Printf("↩️ Discord delete -> Sneedchat (sneed_id=%d)", sneedID)
	db.sneedClient.SendCommand(fmt.Sprintf("/delete %d", sneedID))
}

func (db *DiscordBridge) onSneedMessage(msg map[string]interface{}) {
	username, _ := msg["username"].(string)
	rawContent, _ := msg["content"].(string)
	content := bbcodeToMarkdown(rawContent)
	messageID, _ := msg["message_id"].(int)
	
	// Replace bridge username mentions with Discord ping
	if db.config.BridgeUsername != "" && db.config.DiscordPingUserID != "" {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)@%s(?:\W|$)`, regexp.QuoteMeta(db.config.BridgeUsername)))
		content = pattern.ReplaceAllString(content, fmt.Sprintf("<@%s>", db.config.DiscordPingUserID))
	}

	// Get avatar URL
	var avatarURL string
	if raw, ok := msg["raw"].(SneedMessage); ok {
		if author, ok := raw.Author["avatar_url"].(string); ok {
			if strings.HasPrefix(author, "/") {
				avatarURL = "https://kiwifarms.st" + author
			} else {
				avatarURL = author
			}
		}
	}

	// Send via webhook
	webhookID, webhookToken := parseWebhookURL(db.config.DiscordWebhookURL)
	params := &discordgo.WebhookParams{
		Content:   content,
		Username:  username,
		AvatarURL: avatarURL,
	}

	sent, err := db.session.WebhookExecute(webhookID, webhookToken, true, params)
	if err != nil {
		log.Printf("❌ Failed to send Sneed → Discord webhook message: %v", err)
		return
	}

	log.Printf("✅ Sent Sneedchat → Discord: %s", username)

	// Map IDs
	if messageID > 0 && sent != nil {
		discordMsgID := parseMessageID(sent.ID)
		db.sneedToDiscord.Set(messageID, discordMsgID)
		db.discordToSneed.Set(discordMsgID, messageID)
		db.sneedUsernames.Set(messageID, username)
	}
}

func (db *DiscordBridge) handleSneedEdit(sneedID int, newContent string) {
	discordMsgIDInt, exists := db.sneedToDiscord.Get(sneedID)
	if !exists {
		return
	}

	discordMsgID := discordMsgIDInt.(int)
	parsed := bbcodeToMarkdown(newContent)

	webhookID, webhookToken := parseWebhookURL(db.config.DiscordWebhookURL)
	edit := &discordgo.WebhookEdit{
		Content: &parsed,
	}

	_, err := db.session.WebhookMessageEdit(webhookID, webhookToken, fmt.Sprintf("%d", discordMsgID), edit)
	if err != nil {
		log.Printf("❌ Failed to edit Discord message id=%d: %v", discordMsgID, err)
		return
	}

	log.Printf("✏️ Edited Discord (webhook) message id=%d (sneed_id=%d)", discordMsgID, sneedID)
}

func (db *DiscordBridge) handleSneedDelete(sneedID int) {
	discordMsgIDInt, exists := db.sneedToDiscord.Get(sneedID)
	if !exists {
		return
	}

	discordMsgID := discordMsgIDInt.(int)

	webhookID, webhookToken := parseWebhookURL(db.config.DiscordWebhookURL)
	err := db.session.WebhookMessageDelete(webhookID, webhookToken, fmt.Sprintf("%d", discordMsgID))
	if err != nil {
		log.Printf("❌ Failed to delete Discord message id=%d: %v", discordMsgID, err)
		return
	}

	log.Printf("🗑️ Deleted Discord (webhook) message id=%d (sneed_id=%d)", discordMsgID, sneedID)
	db.sneedToDiscord.Delete(sneedID)
	db.discordToSneed.Delete(discordMsgID)
	db.sneedUsernames.Delete(sneedID)
}

func (db *DiscordBridge) onSneedConnect() {
	log.Println("🟢 Sneedchat connected")
	db.session.UpdateStatusComplex(discordgo.UpdateStatusData{Status: "online"})

	// Update the most recent outage message
	db.outageMessagesMu.Lock()
	if len(db.outageMessages) > 0 {
		lastMessage := db.outageMessages[len(db.outageMessages)-1]
		elapsed := int(time.Since(db.outageStart).Seconds())
		embed := &discordgo.MessageEmbed{
			Title:       "🌉 Bridge Status",
			Description: "✅ **Sneedchat reconnected**",
			Color:       0x00FF00,
			Fields: []*discordgo.MessageEmbedField{
				{Name: "Downtime", Value: fmt.Sprintf("%ds", elapsed), Inline: true},
				{Name: "Reconnect Attempts", Value: fmt.Sprintf("%d", db.sneedClient.reconnectAttempts), Inline: true},
				{Name: "Room ID", Value: fmt.Sprintf("%d", db.sneedClient.roomID), Inline: true},
			},
		}

		db.session.ChannelMessageEditEmbed(lastMessage.ChannelID, lastMessage.ID, embed)
		
		// Schedule cleanup of all outage messages after 2 minutes
		go db.cleanupOutageMessages(2 * time.Minute)
	}
	db.outageMessagesMu.Unlock()

	// Flush queued messages
	go db.flushQueuedMessages()
}

func (db *DiscordBridge) cleanupOutageMessages(delay time.Duration) {
	time.Sleep(delay)
	
	db.outageMessagesMu.Lock()
	messagesToDelete := make([]*discordgo.Message, len(db.outageMessages))
	copy(messagesToDelete, db.outageMessages)
	db.outageMessages = db.outageMessages[:0] // Clear the slice
	db.outageMessagesMu.Unlock()
	
	log.Printf("🧹 Cleaning up %d old outage notification(s)", len(messagesToDelete))
	
	for _, msg := range messagesToDelete {
		err := db.session.ChannelMessageDelete(msg.ChannelID, msg.ID)
		if err != nil {
			log.Printf("Failed to delete outage message %s: %v", msg.ID, err)
		}
	}
	
	if len(messagesToDelete) > 0 {
		log.Println("✅ Outage notifications cleaned up")
	}
}

func (db *DiscordBridge) onSneedDisconnect() {
	log.Println("🔴 Sneedchat disconnected")
	db.session.UpdateStatusComplex(discordgo.UpdateStatusData{Status: "idle"})

	db.outageStart = time.Now()
	embed := &discordgo.MessageEmbed{
		Title:       "🌉 Bridge Status",
		Description: "⚠️ **Sneedchat disconnected**",
		Color:       0xFF0000,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Outage Duration", Value: "0s", Inline: true},
			{Name: "Reconnect Attempts", Value: "0", Inline: true},
			{Name: "Room ID", Value: fmt.Sprintf("%d", db.sneedClient.roomID), Inline: true},
		},
	}

	msg, err := db.session.ChannelMessageSendEmbed(db.config.DiscordChannelID, embed)
	if err != nil {
		log.Printf("Failed to send outage notice: %v", err)
		return
	}

	// Add to outage messages list
	db.outageMessagesMu.Lock()
	db.outageMessages = append(db.outageMessages, msg)
	db.outageMessagesMu.Unlock()

	// Start updater for this specific message
	go db.outageUpdater(msg)
}

func (db *DiscordBridge) outageUpdater(msg *discordgo.Message) {
	ticker := time.NewTicker(OutageUpdateInterval)
	defer ticker.Stop()

	for {
		<-ticker.C

		// Stop updating if Sneedchat is connected
		if db.sneedClient.connected {
			return
		}

		elapsed := int(time.Since(db.outageStart).Seconds())
		embed := &discordgo.MessageEmbed{
			Title:       "🌉 Bridge Status",
			Description: "⚠️ **Sneedchat outage ongoing**",
			Color:       0xFF0000,
			Fields: []*discordgo.MessageEmbedField{
				{Name: "Outage Duration", Value: fmt.Sprintf("%ds", elapsed), Inline: true},
				{Name: "Reconnect Attempts", Value: fmt.Sprintf("%d", db.sneedClient.reconnectAttempts), Inline: true},
				{Name: "Room ID", Value: fmt.Sprintf("%d", db.sneedClient.roomID), Inline: true},
			},
		}

		db.session.ChannelMessageEditEmbed(msg.ChannelID, msg.ID, embed)
	}
}

func (db *DiscordBridge) flushQueuedMessages() {
	db.queuedOutboundMu.Lock()
	queued := make([]QueuedMessage, len(db.queuedOutbound))
	copy(queued, db.queuedOutbound)
	db.queuedOutbound = db.queuedOutbound[:0]
	db.queuedOutboundMu.Unlock()

	if len(queued) == 0 {
		return
	}

	log.Printf("Flushing %d queued messages to Sneedchat", len(queued))

	for _, msg := range queued {
		age := time.Since(msg.Timestamp)
		if age > QueuedMessageTTL {
			db.session.ChannelMessageSend(msg.ChannelID, fmt.Sprintf("❌ Failed to deliver message queued %ds ago (expired)", int(age.Seconds())))
			continue
		}

		sent := db.sneedClient.SendMessage(msg.Content)
		if sent {
			db.recentOutboundMu.Lock()
			db.recentOutbound = append(db.recentOutbound, OutboundEntry{
				DiscordID: msg.DiscordID,
				Content:   msg.Content,
				Timestamp: time.Now(),
				Mapped:    false,
			})
			if len(db.recentOutbound) > ProcessedCacheSize {
				db.recentOutbound = db.recentOutbound[1:]
			}
			db.recentOutboundMu.Unlock()

			db.session.ChannelMessageSend(msg.ChannelID, "✅ Queued message delivered to Sneedchat after reconnect.")
		}
	}
}

func (db *DiscordBridge) recentOutboundIter() []map[string]interface{} {
	db.recentOutboundMu.Lock()
	defer db.recentOutboundMu.Unlock()

	result := make([]map[string]interface{}, len(db.recentOutbound))
	for i, entry := range db.recentOutbound {
		result[i] = map[string]interface{}{
			"discord_id": entry.DiscordID,
			"content":    entry.Content,
			"ts":         entry.Timestamp,
			"mapped":     entry.Mapped,
		}
	}
	return result
}

func (db *DiscordBridge) mapDiscordSneed(discordID, sneedID int, username string) {
	db.discordToSneed.Set(discordID, sneedID)
	db.sneedToDiscord.Set(sneedID, discordID)
	db.sneedUsernames.Set(sneedID, username)
	log.Printf("Mapped sneed_id=%d <-> discord_id=%d (username='%s')", sneedID, discordID, username)
}

// -----------------------------
// Helper Functions
// -----------------------------
func parseWebhookURL(webhookURL string) (string, string) {
	parts := strings.Split(webhookURL, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

func parseMessageID(id string) int {
	parsed, _ := strconv.ParseInt(id, 10, 64)
	return int(parsed)
}

// -----------------------------
// Main
// -----------------------------
func main() {
	envFile := ".env"
	if len(os.Args) > 1 {
		for i, arg := range os.Args {
			if arg == "--env" && i+1 < len(os.Args) {
				envFile = os.Args[i+1]
			}
		}
	}

	config, err := loadConfig(envFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Using .env file: %s", envFile)
	log.Printf("Using Sneedchat room ID: %d", config.SneedchatRoomID)
	log.Printf("Bridge username: %s", config.BridgeUsername)

	// Start cookie service
	cookieService, err := NewCookieRefreshService(config.BridgeUsername, config.BridgePassword, "kiwifarms.st")
	if err != nil {
		log.Fatalf("Failed to create cookie service: %v", err)
	}

	cookieService.Start()
	log.Println("⏳ Waiting for initial cookie...")
	cookieService.WaitForCookie()

	initialCookie := cookieService.GetCurrentCookie()
	if initialCookie == "" {
		log.Fatal("❌ Failed to obtain initial cookie, cannot start bridge")
	}

	// Create Sneedchat client
	sneedClient := NewSneedChatClient(initialCookie, config.SneedchatRoomID, cookieService)

	// Create Discord bridge
	bridge, err := NewDiscordBridge(config, sneedClient)
	if err != nil {
		log.Fatalf("Failed to create Discord bridge: %v", err)
	}

	// Start bridge
	if err := bridge.Start(); err != nil {
		log.Fatalf("Failed to start Discord bridge: %v", err)
	}

	log.Println("🌉 Discord-Sneedchat Bridge started successfully")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutdown signal received, cleaning up...")

	// Cleanup
	bridge.Stop()
	sneedClient.Disconnect()
	cookieService.Stop()

	log.Println("Bridge stopped successfully")
}