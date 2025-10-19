package discord

import (
	"fmt"
	"log"

	"github.com/bwmarrin/discordgo"
	"local/sneedchatbridge/config"
	"local/sneedchatbridge/sneed"
)

type Bridge struct {
	cfg     *config.Config
	session *discordgo.Session
	sneed   *sneed.Client
}

func NewBridge(cfg *config.Config, sneedClient *sneed.Client) (*Bridge, error) {
	s, err := discordgo.New("Bot " + cfg.DiscordBotToken)
	if err != nil {
		return nil, err
	}
	b := &Bridge{cfg: cfg, session: s, sneed: sneedClient}
	s.AddHandler(b.onReady)
	s.AddHandler(b.onMessage)
	return b, nil
}

func (b *Bridge) Start() error {
	b.session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent
	if err := b.session.Open(); err != nil {
		return err
	}
	return nil
}

func (b *Bridge) Stop() {
	b.session.Close()
}

func (b *Bridge) onReady(s *discordgo.Session, r *discordgo.Ready) {
	log.Printf("🤖 Discord bot ready: %s (%s)", r.User.Username, r.User.ID)
}

func (b *Bridge) onMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author == nil || m.Author.Bot {
		return
	}
	if m.ChannelID != b.cfg.DiscordChannelID {
		return
	}
	// Simple pass-through to Sneedchat (extend with attachments, mapping, etc., as in your original)
	if ok := b.sneed.Send(m.Content); !ok {
		s.ChannelMessageSend(m.ChannelID, "⚠️ Sneedchat appears offline. Message not sent.")
		return
	}
	log.Printf("📤 Discord → Sneedchat: %s: %s", m.Author.Username, m.Content)
	// Basic echo confirmation
	_, _ = s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Sent to Sneedchat: %s", m.Content))
}
