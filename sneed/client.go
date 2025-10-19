package sneed

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"local/sneedchatbridge/cookie"
	"local/sneedchatbridge/utils"
)

const (
	ProcessedCacheSize     = 250
	ReconnectInterval      = 7 * time.Second
	MappingCacheSize       = 1000
	MappingCleanupInterval = 5 * time.Minute
	MappingMaxAge          = 1 * time.Hour
	OutboundMatchWindow    = 60 * time.Second
)

type Client struct {
	wsURL   string
	roomID  int
	cookies *cookie.CookieRefreshService

	conn      *websocket.Conn
	connected bool
	mu        sync.RWMutex

	lastMessage time.Time
	stopCh      chan struct{}
	wg          sync.WaitGroup

	// processed
	processedMu         sync.Mutex
	processedMessageIDs []int

	messageEditDates *utils.BoundedMap

	// event callbacks
	OnMessage    func(map[string]interface{})
	OnEdit       func(int, string)
	OnDelete     func(int)
	OnConnect    func()
	OnDisconnect func()

	// outbound correlation for echo suppression / mapping
	recentOutboundIter func() []map[string]interface{}
	mapDiscordSneed    func(int, int, string)

	bridgeUserID   int
	bridgeUsername string
}

func NewClient(roomID int, cookieSvc *cookie.CookieRefreshService) *Client {
	return &Client{
		wsURL:               "wss://kiwifarms.st:9443/chat.ws",
		roomID:              roomID,
		cookies:             cookieSvc,
		stopCh:              make(chan struct{}),
		processedMessageIDs: make([]int, 0, ProcessedCacheSize),
		messageEditDates:    utils.NewBoundedMap(MappingCacheSize, MappingMaxAge),
		lastMessage:         time.Now(),
	}
}

func (c *Client) SetBridgeIdentity(userID int, username string) {
	c.bridgeUserID = userID
	c.bridgeUsername = username
}

func (c *Client) Connect() error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	headers := http.Header{}
	if ck := c.cookies.GetCurrentCookie(); ck != "" {
		headers.Add("Cookie", ck)
	}

	log.Printf("Connecting to Sneedchat room %d", c.roomID)
	conn, _, err := websocket.DefaultDialer.Dial(c.wsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket connection failed: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.lastMessage = time.Now()
	c.mu.Unlock()

	c.wg.Add(3)
	go c.readLoop()
	go c.heartbeatLoop()
	go c.joinRoom()

	log.Printf("✅ Successfully connected to Sneedchat room %d", c.roomID)
	if c.OnConnect != nil {
		c.OnConnect()
	}
	return nil
}

func (c *Client) joinRoom() {
	defer c.wg.Done()
	c.Send(fmt.Sprintf("/join %d", c.roomID))
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	defer c.handleDisconnect()

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
			return
		}
		c.lastMessage = time.Now()
		c.handleIncoming(string(message))
	}
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
	return true
}

func (c *Client) handleDisconnect() {
	select {
	case <-c.stopCh:
		return
	default:
	}
	c.mu.Lock()
	c.connected = false
	if c.conn != nil {
		c.conn.Close()
	}
	c.mu.Unlock()
	log.Println("🔴 Sneedchat disconnected")
	if c.OnDisconnect != nil {
		c.OnDisconnect()
	}
	time.Sleep(ReconnectInterval)
	_ = c.Connect()
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
		return
	}

	// top-level deletes
	if payload.Delete != nil {
		var ids []int
		switch v := payload.Delete.(type) {
		case float64:
			ids = []int{int(v)}
		case []interface{}:
			for _, x := range v {
				if fid, ok := x.(float64); ok {
					ids = append(ids, int(fid))
				}
			}
		}
		for _, id := range ids {
			c.messageEditDates.Delete(id)
			c.removeFromProcessed(id)
			if c.OnDelete != nil {
				c.OnDelete(id)
			}
		}
	}

	// messages list or single
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

	editDate := m.MessageEditDate
	deleted := m.Deleted || m.IsDeleted
	if deleted {
		c.messageEditDates.Delete(m.MessageID)
		c.removeFromProcessed(m.MessageID)
		if c.OnDelete != nil {
			c.OnDelete(m.MessageID)
		}
		return
	}

	// suppress bridge echoes
	if (c.bridgeUserID > 0 && userID == c.bridgeUserID) ||
		(c.bridgeUsername != "" && username == c.bridgeUsername) {
		// correlate outbound -> map IDs
		if m.MessageID > 0 && c.recentOutboundIter != nil && c.mapDiscordSneed != nil {
			now := time.Now()
			for _, entry := range c.recentOutboundIter() {
				if mapped, ok := entry["mapped"].(bool); ok && mapped {
					continue
				}
				content, _ := entry["content"].(string)
				if ts, ok := entry["ts"].(time.Time); ok {
					if content == messageText && now.Sub(ts) <= OutboundMatchWindow {
						if discordID, ok := entry["discord_id"].(int); ok {
							c.mapDiscordSneed(discordID, m.MessageID, username)
							entry["mapped"] = true
							break
						}
					}
				}
			}
		}
		c.addToProcessed(m.MessageID)
		c.messageEditDates.Set(m.MessageID, editDate)
		return
	}

	// de-dup / edits
	if c.isProcessed(m.MessageID) {
		if prev, exists := c.messageEditDates.Get(m.MessageID); exists {
			if editDate > prev.(int) {
				c.messageEditDates.Set(m.MessageID, editDate)
				if c.OnEdit != nil {
					c.OnEdit(m.MessageID, messageText)
				}
			}
		}
		return
	}

	// new message
	c.addToProcessed(m.MessageID)
	c.messageEditDates.Set(m.MessageID, editDate)

	if c.OnMessage != nil {
		c.OnMessage(map[string]interface{}{
			"username":   username,
			"content":    messageText,
			"message_id": m.MessageID,
			"author_id":  userID,
			"raw":        m,
		})
	}
}

func (c *Client) isProcessed(id int) bool {
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	for _, x := range c.processedMessageIDs {
		if x == id {
			return true
		}
	}
	return false
}

func (c *Client) addToProcessed(id int) {
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	c.processedMessageIDs = append(c.processedMessageIDs, id)
	if len(c.processedMessageIDs) > ProcessedCacheSize {
		c.processedMessageIDs = c.processedMessageIDs[1:]
	}
}

func (c *Client) removeFromProcessed(id int) {
	c.processedMu.Lock()
	defer c.processedMu.Unlock()
	for i, x := range c.processedMessageIDs {
		if x == id {
			c.processedMessageIDs = append(c.processedMessageIDs[:i], c.processedMessageIDs[i+1:]...)
			return
		}
	}
}

// helpers for mapping in bridge
func (c *Client) SetOutboundIter(f func() []map[string]interface{}) {
	c.recentOutboundIter = f
}
func (c *Client) SetMapDiscordSneed(f func(int, int, string)) {
	c.mapDiscordSneed = f
}

// expose helper for mention replacement
func ReplaceBridgeMention(content, bridgeUsername, pingID string) string {
	if bridgeUsername == "" || pingID == "" {
		return content
	}
	pat := regexp.MustCompile(fmt.Sprintf(`(?i)@%s(?:\W|$)`, regexp.QuoteMeta(bridgeUsername)))
	return pat.ReplaceAllString(content, fmt.Sprintf("<@%s>", pingID))
}
