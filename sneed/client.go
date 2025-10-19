package sneed

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"local/sneedchatbridge/cookie"
)

type Client struct {
	wsURL   string
	roomID  int
	cookies *cookie.RefreshService

	conn      *websocket.Conn
	connected bool
	mu        sync.RWMutex

	lastMessage time.Time
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

func NewClient(roomID int, cookieSvc *cookie.RefreshService) *Client {
	return &Client{
		wsURL:   "wss://kiwifarms.st:9443/chat.ws",
		roomID:  roomID,
		cookies: cookieSvc,
		stopCh:  make(chan struct{}),
	}
}

func (c *Client) Connect() error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	headers := http.Header{}
	headers.Add("Cookie", c.cookies.GetCurrentCookie())

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
		_ = message // plug in your existing JSON handling if needed
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
	time.Sleep(7 * time.Second)
	_ = c.Connect() // try once; your original had a loop — add if desired
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
