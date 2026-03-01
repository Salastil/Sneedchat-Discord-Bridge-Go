package sneed

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"local/sneedchatbridge/cookie"
	"local/sneedchatbridge/utils"
)

const (
	ProcessedCacheSize     = 1000
	ReconnectInterval      = 7 * time.Second
	MappingCacheSize       = 1000
	MappingCleanupInterval = 5 * time.Minute
	MappingMaxAge          = 1 * time.Hour
	OutboundMatchWindow    = 60 * time.Second
)

// socketTLSConfig mirrors the config used by sockchat: broad cipher suite list
// to avoid KiwiFlare TLS fingerprint detection on the WebSocket upgrade.
func socketTLSConfig() *tls.Config {
	suites := slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites())
	ids := make([]uint16, len(suites))
	for i, s := range suites {
		ids[i] = s.ID
	}
	return &tls.Config{CipherSuites: ids}
}


type Client struct {
	wsURL   string
	roomID  int
	session *cookie.SessionService

	dialer    websocket.Dialer
	conn      *websocket.Conn
	connected bool
	mu        sync.RWMutex

	lastMessage time.Time
	stopCh      chan struct{}
	wg          sync.WaitGroup

	processedMu      sync.Mutex
	processedUUIDs   []string
	messageEditDates *utils.BoundedMap

	OnMessage    func(map[string]interface{})
	OnEdit       func(string, string)
	OnDelete     func(string)
	OnConnect    func()
	OnDisconnect func()

	recentOutboundIter func() []map[string]interface{}
	mapDiscordSneed    func(string, int, string)

	bridgeUserID     int
	bridgeUsername   string
	baseLoopsStarted bool
	debug            bool
}

func NewClient(roomID int, session *cookie.SessionService, debug bool) *Client {
	tr := session.Transport()

	return &Client{
		wsURL:   "wss://kiwifarms.st:9443/chat.ws",
		roomID:  roomID,
		session: session,
		debug:   debug,
		dialer: websocket.Dialer{
			EnableCompression: true,
			NetDialContext:    tr.DialContext,
			TLSClientConfig:   tr.TLSClientConfig,
		},
		stopCh:              make(chan struct{}),
		processedUUIDs: make([]string, 0, ProcessedCacheSize),
		messageEditDates:    utils.NewBoundedMap(MappingCacheSize, MappingMaxAge),
		lastMessage:         time.Now(),
	}
}

func (c *Client) SetBridgeIdentity(userID int, username string) {
	c.bridgeUserID = userID
	c.bridgeUsername = username
}

func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Exclude ttrs_clearance — must be solved fresh for port 9443.
	headers := http.Header{
		"Cookie": {c.session.CookieStringForWS()},
	}

	log.Printf("Connecting to Sneedchat room %d", c.roomID)
	if c.debug {
		log.Printf("🍪 Dial cookies: %s", headers.Get("Cookie"))
	}

	conn, resp, err := c.dialer.DialContext(ctx, c.wsURL, headers)
	if err != nil {
		if resp != nil && resp.StatusCode == 203 {
			log.Println("⚠️ Got 203 on WebSocket dial — solving challenge...")
			body := make([]byte, 0)
			if resp.Body != nil {
				buf := make([]byte, 8192)
				n, _ := resp.Body.Read(buf)
				body = buf[:n]
				resp.Body.Close()
			}
			clearance, serr := c.session.SolveForHost(ctx, body)
			if serr != nil {
				return fmt.Errorf("PoW solve for WS endpoint: %w", serr)
			}
			wsBase := c.session.CookieStringForWS()
			headers["Cookie"] = []string{wsBase + "; ttrs_clearance=" + clearance}
			if c.debug {
				log.Printf("🍪 Retry dial cookies: %s", headers.Get("Cookie"))
			}
			conn, _, err = c.dialer.DialContext(ctx, c.wsURL, headers)
			if err != nil {
				return fmt.Errorf("websocket connection failed after PoW solve: %w", err)
			}
		} else {
			return fmt.Errorf("websocket connection failed: %w", err)
		}
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.lastMessage = time.Now()
	c.mu.Unlock()

	if !c.baseLoopsStarted {
		c.baseLoopsStarted = true
		c.wg.Add(2)
		go c.heartbeatLoop()
		go c.cleanupLoop()
	}

	c.wg.Add(1)
	go c.readLoop(ctx)

	c.Send(fmt.Sprintf("/join %d", c.roomID))
	log.Printf("✅ Successfully connected to Sneedchat room %d", c.roomID)
	if c.OnConnect != nil {
		c.OnConnect()
	}
	return nil
}

func (c *Client) joinRoom() {
	c.Send(fmt.Sprintf("/join %d", c.roomID))
}

func (c *Client) readLoop(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		if conn == nil {
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Sneedchat read error: %v", err)
			c.handleDisconnect(ctx)
			return
		}

		raw := string(message)

		// Server sends plaintext "cannot join" when session has expired.
		if isCannotJoin(raw) {
			log.Println("⚠️ 'cannot join' received — refreshing session and reconnecting...")
			if rerr := c.session.Refresh(ctx); rerr != nil {
				log.Printf("❌ Session refresh failed: %v", rerr)
			}
			c.handleDisconnect(ctx)
			return
		}

		c.mu.Lock()
		c.lastMessage = time.Now()
		c.mu.Unlock()

		if c.debug {
			preview := raw
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			log.Printf("📨 WS recv: %s", preview)
		}

		c.handleIncoming(raw)
	}
}

func isCannotJoin(msg string) bool {
	return len(msg) > 0 && !isJSON(msg) && len(msg) >= 11 && msg == "cannot join"
}

func isJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.mu.RLock()
			connected := c.connected
			conn := c.conn
			c.mu.RUnlock()
			if connected && time.Since(c.lastMessage) > 60*time.Second && conn != nil {
				_ = conn.WriteMessage(websocket.TextMessage, []byte("/ping"))
			}
		case <-c.stopCh:
			return
		}
	}
}

func (c *Client) cleanupLoop() {
	defer c.wg.Done()
	t := time.NewTicker(MappingCleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			removed := c.messageEditDates.CleanupOldEntries()
			if removed > 0 {
				log.Printf("🧹 Cleaned up %d old message tracking entries", removed)
			}
		case <-c.stopCh:
			return
		}
	}
}

func (c *Client) Send(s string) bool {
	c.mu.RLock()
	conn := c.conn
	ok := c.connected && conn != nil
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(s)); err != nil {
		log.Printf("Sneedchat write error: %v", err)
		return false
	}
	if c.debug {
		preview := s
		if len(preview) > 120 {
			preview = preview[:120] + "..."
		}
		log.Printf("📤 WS sent: %s", preview)
	}
	return true
}

func (c *Client) handleDisconnect(ctx context.Context) {
	select {
	case <-c.stopCh:
		return
	default:
	}

	c.mu.Lock()
	c.connected = false
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()

	log.Println("🔴 Sneedchat disconnected")
	if c.OnDisconnect != nil {
		c.OnDisconnect()
	}

	delay := ReconnectInterval
	maxDelay := 2 * time.Minute
	attempt := 0

	for {
		select {
		case <-c.stopCh:
			log.Println("Reconnection cancelled — bridge stopping")
			return
		case <-time.After(delay):
			attempt++
			log.Printf("🔄 Reconnection attempt #%d...", attempt)

			if err := c.Connect(ctx); err != nil {
				log.Printf("⚠️ Reconnect attempt #%d failed: %v", attempt, err)
				delay *= 2
				if delay > maxDelay {
					delay = maxDelay
				}
				continue
			}

			log.Println("🟢 Reconnected successfully")
			time.Sleep(2 * time.Second)
			c.joinRoom()
			c.Send("/ping")
			log.Printf("📍 Rejoined Sneedchat room %d after reconnect", c.roomID)
			return
		}
	}
}

func (c *Client) Disconnect() {
	close(c.stopCh)
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connected = false
	c.mu.Unlock()
	c.wg.Wait()
}

func (c *Client) handleIncoming(raw string) {
	var payload SneedPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		if c.debug {
			log.Printf("⚠️ WS parse error: %v | raw: %.100s", err, raw)
		}
		return
	}

	if c.debug {
		log.Printf("📦 payload: msgs=%d msg=%v del=%v", len(payload.Messages), payload.Message != nil, payload.Delete != nil)
	}

	for _, uuid := range payload.Delete {
		if uuid == "" {
			continue
		}
		c.messageEditDates.Delete(uuid)
		c.removeFromProcessed(uuid)
		if c.OnDelete != nil {
			c.OnDelete(uuid)
		}
	}

	var messages []SneedMessage
	if len(payload.Messages) > 0 {
		messages = payload.Messages
	} else if payload.Message != nil {
		messages = []SneedMessage{*payload.Message}
	}
	for _, m := range messages {
		c.processMessage(m)
	}
}

func (c *Client) processMessage(m SneedMessage) {
	username := "Unknown"
	var userID int
	if a, ok := m.Author["username"].(string); ok {
		username = a
	}
	if id, ok := m.Author["id"].(float64); ok {
		userID = int(id)
	}

	messageText := m.MessageRaw
	if messageText == "" {
		messageText = m.Message
	}
	messageText = html.UnescapeString(messageText)

	uuid := m.MessageUUID
	editDate := m.MessageEditDate
	deleted := m.Deleted || m.IsDeleted
	if deleted {
		c.messageEditDates.Delete(uuid)
		c.removeFromProcessed(uuid)
		if c.OnDelete != nil {
			c.OnDelete(uuid)
		}
		return
	}

	if (c.bridgeUserID > 0 && userID == c.bridgeUserID) ||
		(c.bridgeUsername != "" && username == c.bridgeUsername) {
		if uuid != "" && c.recentOutboundIter != nil && c.mapDiscordSneed != nil {
			now := time.Now()
			for _, entry := range c.recentOutboundIter() {
				if mapped, ok := entry["mapped"].(bool); ok && mapped {
					continue
				}
				content, _ := entry["content"].(string)
				if ts, ok := entry["ts"].(time.Time); ok {
					if content == messageText && now.Sub(ts) <= OutboundMatchWindow {
						if discordID, ok := entry["discord_id"].(int); ok {
							c.mapDiscordSneed(uuid, discordID, username)
							entry["mapped"] = true
							break
						}
					}
				}
			}
		}
		c.addToProcessed(uuid)
		c.messageEditDates.Set(uuid, editDate)
		return
	}

	if c.isProcessed(uuid) {
		if prev, exists := c.messageEditDates.Get(uuid); exists {
			if editDate > prev.(int) {
				c.messageEditDates.Set(uuid, editDate)
				if c.OnEdit != nil {
					c.OnEdit(uuid, messageText)
				}
			}
		}
		return
	}

	c.addToProcessed(uuid)
	c.messageEditDates.Set(uuid, editDate)

	if c.OnMessage != nil {
		c.OnMessage(map[string]interface{}{
			"username":     username,
			"content":      messageText,
			"message_uuid": uuid,
			"message_id":   m.MessageID,
			"author_id":    userID,
			"raw":          m,
		})
	}
}

func (c *Client) isProcessed(uuid string) bool {
	if uuid == "" {
		return false
	}
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	for _, x := range c.processedUUIDs {
		if x == uuid {
			return true
		}
	}
	return false
}

func (c *Client) addToProcessed(uuid string) {
	if uuid == "" {
		return
	}
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	c.processedUUIDs = append(c.processedUUIDs, uuid)
	if len(c.processedUUIDs) > ProcessedCacheSize {
		excess := len(c.processedUUIDs) - ProcessedCacheSize
		c.processedUUIDs = c.processedUUIDs[excess:]
	}
}

func (c *Client) removeFromProcessed(uuid string) {
	if uuid == "" {
		return
	}
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	for i, x := range c.processedUUIDs {
		if x == uuid {
			c.processedUUIDs = append(c.processedUUIDs[:i], c.processedUUIDs[i+1:]...)
			return
		}
	}
}

func (c *Client) SetOutboundIter(f func() []map[string]interface{}) {
	c.recentOutboundIter = f
}

func (c *Client) SetMapDiscordSneed(f func(string, int, string)) {
	c.mapDiscordSneed = f
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func ReplaceBridgeMention(content, bridgeUsername, pingID string) string {
	if bridgeUsername == "" || pingID == "" {
		return content
	}
	pat := regexp.MustCompile(fmt.Sprintf(`(?i)@%s(?:\W|$)`, regexp.QuoteMeta(bridgeUsername)))
	return pat.ReplaceAllString(content, fmt.Sprintf("<@%s>", pingID))
}

// Ensure socketTLSConfig is used (referenced in NewClient via session.Transport()).
var _ = socketTLSConfig
