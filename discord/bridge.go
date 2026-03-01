package discord

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bwmarrin/discordgo"
	"local/sneedchatbridge/config"
	"local/sneedchatbridge/media"
	"local/sneedchatbridge/sneed"
	"local/sneedchatbridge/utils"
)

const (
	MaxAttachments              = 4
	ProcessedCacheSize          = 250
	MappingCacheSize            = 1000
	MappingMaxAge               = 1 * time.Hour
	MappingCleanupInterval      = 5 * time.Minute
	QueuedMessageTTL            = 90 * time.Second
	OutageUpdateInterval        = 10 * time.Second
	OutboundMatchWindow         = 60 * time.Second
	OutageEmbedColorActive      = 0xF1C40F
	OutageEmbedColorFixed       = 0x2ECC71
	UploadStatusColorPending    = 0x3498DB
	UploadStatusColorSuccess    = 0x2ECC71
	UploadStatusColorFailed     = 0xE74C3C
	UploadDeliveryTimeout       = 2 * time.Minute
	UploadStatusCleanupDelay    = 15 * time.Second
	UploadStatusFailureLifetime = 60 * time.Second
)

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

type Bridge struct {
	cfg      *config.Config
	session  *discordgo.Session
	sneed    *sneed.Client
	mediaSvc media.Service

	sneedToDiscord *utils.BoundedMap
	discordToSneed *utils.BoundedMap
	sneedUsernames *utils.BoundedMap

	recentOutbound   []OutboundEntry
	recentOutboundMu sync.Mutex

	queuedOutbound   []QueuedMessage
	queuedOutboundMu sync.Mutex

	outageNotices       []*discordgo.Message
	outageActiveMessage *discordgo.Message
	outageMessagesMu    sync.Mutex
	outageStart         time.Time

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewBridge(cfg *config.Config, sneedClient *sneed.Client) (*Bridge, error) {
	s, err := discordgo.New("Bot " + cfg.DiscordBotToken)
	if err != nil {
		return nil, err
	}
	mediaSvc, err := media.NewService(cfg.MediaUploadService, &http.Client{Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	b := &Bridge{
		cfg:            cfg,
		session:        s,
		sneed:          sneedClient,
		mediaSvc:       mediaSvc,
		sneedToDiscord: utils.NewBoundedMap(MappingCacheSize, MappingMaxAge),
		discordToSneed: utils.NewBoundedMap(MappingCacheSize, MappingMaxAge),
		sneedUsernames: utils.NewBoundedMap(MappingCacheSize, MappingMaxAge),
		recentOutbound: make([]OutboundEntry, 0, ProcessedCacheSize),
		queuedOutbound: make([]QueuedMessage, 0),
		outageNotices:  make([]*discordgo.Message, 0),
		stopCh:         make(chan struct{}),
	}

	// hook Sneed client callbacks
	sneedClient.OnMessage = b.onSneedMessage
	sneedClient.OnEdit = b.handleSneedEdit
	sneedClient.OnDelete = b.handleSneedDelete
	sneedClient.OnConnect = b.onSneedConnect
	sneedClient.OnDisconnect = b.onSneedDisconnect
	sneedClient.SetOutboundIter(b.recentOutboundIter)
	sneedClient.SetMapDiscordSneed(b.mapDiscordSneed)
	sneedClient.SetBridgeIdentity(cfg.BridgeUserID, cfg.BridgeUsername)

	// Discord event handlers
	s.AddHandler(b.onDiscordReady)
	s.AddHandler(b.onDiscordMessageCreate)
	s.AddHandler(b.onDiscordMessageEdit)
	s.AddHandler(b.onDiscordMessageDelete)

	return b, nil
}

func (b *Bridge) Start() error {
	b.session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent
	if err := b.session.Open(); err != nil {
		return err
	}
	b.wg.Add(1)
	go b.cleanupLoop()
	return nil
}

func (b *Bridge) Stop() {
	close(b.stopCh)
	b.session.Close()
	b.wg.Wait()
}

func (b *Bridge) cleanupLoop() {
	defer b.wg.Done()
	t := time.NewTicker(MappingCleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			removed := 0
			removed += b.sneedToDiscord.CleanupOldEntries()
			removed += b.discordToSneed.CleanupOldEntries()
			removed += b.sneedUsernames.CleanupOldEntries()
			if removed > 0 {
				log.Printf("🧹 Cleaned up %d old message mappings", removed)
			}

			// Cleanup expired queued messages
			b.queuedOutboundMu.Lock()
			now := time.Now()
			filtered := make([]QueuedMessage, 0)
			for _, msg := range b.queuedOutbound {
				if now.Sub(msg.Timestamp) <= QueuedMessageTTL {
					filtered = append(filtered, msg)
				}
			}
			b.queuedOutbound = filtered
			b.queuedOutboundMu.Unlock()

		case <-b.stopCh:
			return
		}
	}
}

func (b *Bridge) onDiscordReady(s *discordgo.Session, r *discordgo.Ready) {
	log.Printf("🤖 Discord bot ready: %s (%s)", r.User.Username, r.User.ID)
}

func (b *Bridge) onDiscordMessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author == nil || m.Author.Bot {
		return
	}
	if m.ChannelID != b.cfg.DiscordChannelID {
		return
	}

	log.Printf("📤 Discord → Sneedchat: %s: %s", m.Author.Username, m.Content)

	contentText := strings.TrimSpace(m.Content)

	if m.ReferencedMessage != nil {
		refDiscordID := parseMessageID(m.ReferencedMessage.ID)
		if sneedUUIDVal, ok := b.discordToSneed.Get(strconv.Itoa(refDiscordID)); ok {
			sneedUUID := sneedUUIDVal.(string)
			if uname, ok2 := b.sneedUsernames.Get(sneedUUID); ok2 {
				contentText = fmt.Sprintf("@%s, %s", uname.(string), contentText)
			}
		}
	}

	var attachmentsBB []string
	var statusMsg *discordgo.Message
	var statusErr error
	if len(m.Attachments) > 0 {
		mention := fmt.Sprintf("<@%s>", m.Author.ID)
		statusMsg, statusErr = b.sendUploadStatusMessage(m.ChannelID, mention, len(m.Attachments))
		if statusErr != nil {
			log.Printf("⚠️ Failed to send upload status message: %v", statusErr)
		}
	}
	if len(m.Attachments) > MaxAttachments {
		return
	}
	ctx := context.Background()
	for idx, att := range m.Attachments {
		if statusMsg != nil {
			desc := fmt.Sprintf("Uploading attachment %d/%d: `%s`", idx+1, len(m.Attachments), att.Filename)
			b.editUploadStatusMessage(statusMsg.ChannelID, statusMsg.ID, b.uploadStatusTitle(""), desc, UploadStatusColorPending)
		}
		url, statusCode, err := b.mediaSvc.Upload(ctx, att)
		if err != nil {
			if statusMsg != nil {
				failureDesc := fmt.Sprintf("Failed to upload `%s`: %v", att.Filename, err)
				if statusCode > 0 {
					failureDesc = fmt.Sprintf("%s\n%s response: HTTP %d", failureDesc, b.mediaServiceDisplayName(), statusCode)
				}
				b.editUploadStatusMessage(statusMsg.ChannelID, statusMsg.ID, b.uploadStatusTitle("failed"), failureDesc, UploadStatusColorFailed)
				b.scheduleUploadStatusDeletion(statusMsg.ChannelID, statusMsg.ID, UploadStatusFailureLifetime)
			}
			return
		}
		if statusMsg != nil {
			desc := fmt.Sprintf("Uploaded %d/%d: `%s` (HTTP %d)", idx+1, len(m.Attachments), att.Filename, statusCode)
			b.editUploadStatusMessage(statusMsg.ChannelID, statusMsg.ID, b.uploadStatusTitle(""), desc, UploadStatusColorPending)
		}

		ct := strings.ToLower(att.ContentType)

		// Images → wrap inside clickable URL with an image preview
		if strings.HasPrefix(ct, "image/") {
			attachmentsBB = append(attachmentsBB,
				fmt.Sprintf("[url=%s][img]%s[/img][/url]", url, url))
		} else {
			// Everything else → plain URL (videos, archives, PDFs, audio, etc)
			attachmentsBB = append(attachmentsBB, url)
		}
	}
	combined := contentText
	if len(attachmentsBB) > 0 {
		if combined != "" {
			combined += "\n"
		}
		combined += strings.Join(attachmentsBB, "\n")
	}

	discordMsgID := parseMessageID(m.ID)
	if b.sneed.Send(combined) {
		b.recentOutboundMu.Lock()
		b.recentOutbound = append(b.recentOutbound, OutboundEntry{
			DiscordID: discordMsgID,
			Content:   combined,
			Timestamp: time.Now(),
			Mapped:    false,
		})
		if len(b.recentOutbound) > ProcessedCacheSize {
			b.recentOutbound = b.recentOutbound[1:]
		}
		b.recentOutboundMu.Unlock()
		if statusMsg != nil {
			b.editUploadStatusMessage(statusMsg.ChannelID, statusMsg.ID, b.uploadStatusTitle(""), "Uploads complete, awaiting Sneedchat confirmation…", UploadStatusColorPending)
			go b.awaitSneedConfirmation(discordMsgID, statusMsg.ChannelID, statusMsg.ID)
		}
	} else {
		b.queuedOutboundMu.Lock()
		b.queuedOutbound = append(b.queuedOutbound, QueuedMessage{
			Content:   combined,
			ChannelID: m.ChannelID,
			Timestamp: time.Now(),
			DiscordID: discordMsgID,
		})
		b.queuedOutboundMu.Unlock()
		if statusMsg != nil {
			b.editUploadStatusMessage(statusMsg.ChannelID, statusMsg.ID, b.uploadStatusTitle("queued"), "Uploads succeeded but Sneedchat is unavailable. Message queued for delivery once the bridge reconnects.", UploadStatusColorPending)
			b.scheduleUploadStatusDeletion(statusMsg.ChannelID, statusMsg.ID, UploadStatusFailureLifetime)
		}
	}
}

func (b *Bridge) onDiscordMessageEdit(s *discordgo.Session, m *discordgo.MessageUpdate) {
	if m.Author == nil || m.Author.Bot {
		return
	}
	if m.ChannelID != b.cfg.DiscordChannelID {
		return
	}
	discordID := parseMessageID(m.ID)
	sneedUUIDVal, ok := b.discordToSneed.Get(strconv.Itoa(discordID))
	if !ok {
		return
	}
	sneedUUID := sneedUUIDVal.(string)
	payload := map[string]interface{}{"uuid": sneedUUID, "message": strings.TrimSpace(m.Content)}
	data, _ := json.Marshal(payload)
	log.Printf("↩️ Discord edit -> Sneedchat (sneed_uuid=%s)", sneedUUID)
	b.sneed.Send(fmt.Sprintf("/edit %s", string(data)))
}

func (b *Bridge) onDiscordMessageDelete(s *discordgo.Session, m *discordgo.MessageDelete) {
	if m.ChannelID != b.cfg.DiscordChannelID {
		return
	}
	discordID := parseMessageID(m.ID)
	sneedUUIDVal, ok := b.discordToSneed.Get(strconv.Itoa(discordID))
	if !ok {
		return
	}
	sneedUUID := sneedUUIDVal.(string)
	log.Printf("↩️ Discord delete -> Sneedchat (sneed_uuid=%s)", sneedUUID)
	b.sneed.Send(fmt.Sprintf("/delete %s", sneedUUID))
}

func (b *Bridge) onSneedMessage(msg map[string]interface{}) {
	username, _ := msg["username"].(string)
	rawContent, _ := msg["content"].(string)
	content := utils.BBCodeToMarkdown(rawContent)

	log.Printf("📄 New Sneed message from %s", username)

	content = sneed.ReplaceBridgeMention(content, b.cfg.BridgeUsername, b.cfg.DiscordPingUserID)

	var avatarURL string
	if raw, ok := msg["raw"].(sneed.SneedMessage); ok {
		if a, ok2 := raw.Author["avatar_url"].(string); ok2 {
			if strings.HasPrefix(a, "/") {
				avatarURL = "https://kiwifarms.st" + a
			} else {
				avatarURL = a
			}
		}
	}

	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	params := &discordgo.WebhookParams{
		Content:   content,
		Username:  username,
		AvatarURL: avatarURL,
	}
	sent, err := b.session.WebhookExecute(webhookID, webhookToken, true, params)
	if err != nil {
		log.Printf("❌ Failed to send Sneed → Discord webhook message: %v", err)
		return
	}

	log.Printf("✅ Sent Sneedchat → Discord: %s", username)

	if sent != nil {
		if uuid, ok := msg["message_uuid"].(string); ok && uuid != "" {
			discordMsgID := parseMessageID(sent.ID)
			b.sneedToDiscord.Set(uuid, discordMsgID)
			b.discordToSneed.Set(strconv.Itoa(discordMsgID), uuid)
			b.sneedUsernames.Set(uuid, username)
		}
	}
}

func (b *Bridge) handleSneedEdit(sneedUUID string, newContent string) {
	discordIDInt, ok := b.sneedToDiscord.Get(sneedUUID)
	if !ok {
		return
	}
	discordID := discordIDInt.(int)
	parsed := utils.BBCodeToMarkdown(newContent)
	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	edit := &discordgo.WebhookEdit{Content: &parsed}
	_, err := b.session.WebhookMessageEdit(webhookID, webhookToken, fmt.Sprintf("%d", discordID), edit)
	if err != nil {
		log.Printf("❌ Failed to edit Discord message id=%d: %v", discordID, err)
		return
	}
	log.Printf("✏️ Edited Discord (webhook) message id=%d (sneed_uuid=%s)", discordID, sneedUUID)
}

func (b *Bridge) handleSneedDelete(sneedUUID string) {
	discordIDInt, ok := b.sneedToDiscord.Get(sneedUUID)
	if !ok {
		return
	}
	discordID := discordIDInt.(int)
	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	err := b.session.WebhookMessageDelete(webhookID, webhookToken, fmt.Sprintf("%d", discordID))
	if err != nil {
		log.Printf("❌ Failed to delete Discord message id=%d: %v", discordID, err)
		return
	}
	log.Printf("🗑️ Deleted Discord (webhook) message id=%d (sneed_uuid=%s)", discordID, sneedUUID)
	b.sneedToDiscord.Delete(sneedUUID)
	b.discordToSneed.Delete(strconv.Itoa(discordID))
	b.sneedUsernames.Delete(sneedUUID)
}

func (b *Bridge) onSneedConnect() {
	log.Println("🟢 Sneedchat connected")
	b.session.UpdateStatusComplex(discordgo.UpdateStatusData{Status: "online"})
	queued := b.queuedMessageCount()
	b.finishOutageNotification(queued)
	go b.flushQueuedMessages()
}

func (b *Bridge) onSneedDisconnect() {
	log.Println("🔴 Sneedchat disconnected")
	b.session.UpdateStatusComplex(discordgo.UpdateStatusData{Status: "idle"})
	b.startOutageNotificationLoop()
}

func (b *Bridge) flushQueuedMessages() {
	b.queuedOutboundMu.Lock()
	queued := make([]QueuedMessage, len(b.queuedOutbound))
	copy(queued, b.queuedOutbound)
	b.queuedOutbound = b.queuedOutbound[:0]
	b.queuedOutboundMu.Unlock()

	if len(queued) == 0 {
		return
	}

	log.Printf("Flushing %d queued messages to Sneedchat", len(queued))

	for _, msg := range queued {
		age := time.Since(msg.Timestamp)
		if age > QueuedMessageTTL {
			continue
		}
		if b.sneed.Send(msg.Content) {
			b.recentOutboundMu.Lock()
			b.recentOutbound = append(b.recentOutbound, OutboundEntry{
				DiscordID: msg.DiscordID,
				Content:   msg.Content,
				Timestamp: time.Now(),
				Mapped:    false,
			})
			if len(b.recentOutbound) > ProcessedCacheSize {
				b.recentOutbound = b.recentOutbound[1:]
			}
			b.recentOutboundMu.Unlock()
			log.Printf("✅ Queued message delivered to Sneedchat after reconnect.")
		}
	}
}

func (b *Bridge) queuedMessageCount() int {
	b.queuedOutboundMu.Lock()
	defer b.queuedOutboundMu.Unlock()
	return len(b.queuedOutbound)
}

func (b *Bridge) startOutageNotificationLoop() {
	b.outageMessagesMu.Lock()
	alreadyRunning := !b.outageStart.IsZero()
	if !alreadyRunning {
		b.outageStart = time.Now()
		go b.outageNotificationLoop()
	}
	b.outageMessagesMu.Unlock()
}

func (b *Bridge) outageNotificationLoop() {
	if !b.updateOutageMessage() {
		return
	}
	ticker := time.NewTicker(OutageUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !b.updateOutageMessage() {
				return
			}
		case <-b.stopCh:
			return
		}
	}
}

func (b *Bridge) updateOutageMessage() bool {
	b.outageMessagesMu.Lock()
	start := b.outageStart
	existing := b.outageActiveMessage
	b.outageMessagesMu.Unlock()

	if start.IsZero() {
		return false
	}

	duration := formatDuration(time.Since(start))
	queued := b.queuedMessageCount()
	desc := fmt.Sprintf("Connection lost **%s** ago.\n%d queued Discord message(s) will be sent automatically once Sneedchat returns.", duration, queued)

	if existing == nil {
		msg, err := b.sendOutageEmbed("Sneedchat outage", desc, OutageEmbedColorActive)
		if err != nil {
			log.Printf("❌ Failed to send outage notification: %v", err)
			return true
		}
		b.outageMessagesMu.Lock()
		b.outageActiveMessage = msg
		toDelete := b.swapOutageNoticesLocked(msg)
		b.outageMessagesMu.Unlock()
		b.deleteOutageMessages(toDelete)
	} else {
		if err := b.editOutageEmbed(existing.ID, "Sneedchat outage", desc, OutageEmbedColorActive); err != nil {
			log.Printf("❌ Failed to update outage notification: %v", err)
		}
	}

	return true
}

func (b *Bridge) finishOutageNotification(queued int) {
	b.outageMessagesMu.Lock()
	start := b.outageStart
	b.outageStart = time.Time{}
	existing := b.outageActiveMessage
	b.outageActiveMessage = nil
	b.outageMessagesMu.Unlock()

	if start.IsZero() {
		return
	}

	duration := formatDuration(time.Since(start))
	desc := fmt.Sprintf("Connection restored after **%s**.\n%d queued Discord message(s) are now being delivered.", duration, queued)

	if existing != nil {
		if err := b.editOutageEmbed(existing.ID, "Sneedchat outage resolved", desc, OutageEmbedColorFixed); err != nil {
			log.Printf("❌ Failed to update outage resolution message: %v", err)
		}
		return
	}

	msg, err := b.sendOutageEmbed("Sneedchat outage resolved", desc, OutageEmbedColorFixed)
	if err != nil {
		log.Printf("❌ Failed to send outage resolution message: %v", err)
		return
	}
	b.outageMessagesMu.Lock()
	toDelete := b.swapOutageNoticesLocked(msg)
	b.outageMessagesMu.Unlock()
	b.deleteOutageMessages(toDelete)
}

func (b *Bridge) deleteOutageMessages(messages []*discordgo.Message) {
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		if err := b.deleteWebhookMessage(msg.ID); err != nil {
			log.Printf("❌ Failed to prune outage notice %s: %v", msg.ID, err)
		}
	}
}

func (b *Bridge) swapOutageNoticesLocked(newMsg *discordgo.Message) []*discordgo.Message {
	toDelete := make([]*discordgo.Message, len(b.outageNotices))
	copy(toDelete, b.outageNotices)
	b.outageNotices = []*discordgo.Message{newMsg}
	return toDelete
}

func (b *Bridge) recentOutboundIter() []map[string]interface{} {
	b.recentOutboundMu.Lock()
	defer b.recentOutboundMu.Unlock()
	res := make([]map[string]interface{}, len(b.recentOutbound))
	for i, e := range b.recentOutbound {
		res[i] = map[string]interface{}{
			"discord_id": e.DiscordID,
			"content":    e.Content,
			"ts":         e.Timestamp,
			"mapped":     e.Mapped,
		}
	}
	return res
}

func (b *Bridge) mapDiscordSneed(sneedUUID string, discordID int, username string) {
	b.discordToSneed.Set(strconv.Itoa(discordID), sneedUUID)
	b.sneedToDiscord.Set(sneedUUID, discordID)
	b.sneedUsernames.Set(sneedUUID, username)
	log.Printf("Mapped sneed_uuid=%s <-> discord_id=%d (username='%s')", sneedUUID, discordID, username)
}

func (b *Bridge) sendUploadStatusMessage(channelID, mention string, attachmentCount int) (*discordgo.Message, error) {
	desc := fmt.Sprintf("Uploading %d attachment(s) from %s…", attachmentCount, mention)
	msg := &discordgo.MessageSend{
		Embeds: []*discordgo.MessageEmbed{buildStatusEmbed(b.uploadStatusTitle(""), desc, UploadStatusColorPending)},
	}
	return b.session.ChannelMessageSendComplex(channelID, msg)
}

func (b *Bridge) uploadStatusTitle(suffix string) string {
	base := fmt.Sprintf("%s upload", b.mediaServiceDisplayName())
	if suffix == "" {
		return base
	}
	return fmt.Sprintf("%s %s", base, suffix)
}

func (b *Bridge) mediaServiceDisplayName() string {
	if b.mediaSvc == nil {
		return "Media"
	}
	name := capitalizeWord(b.mediaSvc.Name())
	if name == "" {
		return "Media"
	}
	return name
}

func (b *Bridge) editUploadStatusMessage(channelID, messageID, title, description string, color int) {
	embed := buildStatusEmbed(title, description, color)
	edit := &discordgo.MessageEdit{
		ID:      messageID,
		Channel: channelID,
		Embeds:  []*discordgo.MessageEmbed{embed},
	}
	if _, err := b.session.ChannelMessageEditComplex(edit); err != nil {
		log.Printf("⚠️ Failed to edit upload status message %s: %v", messageID, err)
	}
}

func (b *Bridge) awaitSneedConfirmation(discordID int, channelID, statusMessageID string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(UploadDeliveryTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ticker.C:
			if _, ok := b.discordToSneed.Get(strconv.Itoa(discordID)); ok {
				desc := "Delivered to Sneedchat."
				b.editUploadStatusMessage(channelID, statusMessageID, b.uploadStatusTitle("complete"), desc, UploadStatusColorSuccess)
				b.scheduleUploadStatusDeletion(channelID, statusMessageID, UploadStatusCleanupDelay)
				return
			}
		case <-timer.C:
			desc := "Uploads finished but no Sneedchat confirmation was observed. Message may have been dropped."
			b.editUploadStatusMessage(channelID, statusMessageID, b.uploadStatusTitle("warning"), desc, UploadStatusColorFailed)
			b.scheduleUploadStatusDeletion(channelID, statusMessageID, UploadStatusFailureLifetime)
			return
		case <-b.stopCh:
			return
		}
	}
}

func (b *Bridge) scheduleUploadStatusDeletion(channelID, messageID string, delay time.Duration) {
	go func() {
		select {
		case <-time.After(delay):
			if err := b.session.ChannelMessageDelete(channelID, messageID); err != nil {
				log.Printf("⚠️ Failed to delete upload status message %s: %v", messageID, err)
			}
		case <-b.stopCh:
		}
	}()
}

func buildStatusEmbed(title, description string, color int) *discordgo.MessageEmbed {
	return &discordgo.MessageEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
}

func capitalizeWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func (b *Bridge) sendOutageEmbed(title, description string, color int) (*discordgo.Message, error) {
	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	embed := buildOutageEmbed(title, description, color)
	params := &discordgo.WebhookParams{Embeds: []*discordgo.MessageEmbed{embed}}
	return b.session.WebhookExecute(webhookID, webhookToken, true, params)
}

func (b *Bridge) editOutageEmbed(messageID, title, description string, color int) error {
	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	embed := buildOutageEmbed(title, description, color)
	embeds := []*discordgo.MessageEmbed{embed}
	edit := &discordgo.WebhookEdit{Embeds: &embeds}
	_, err := b.session.WebhookMessageEdit(webhookID, webhookToken, messageID, edit)
	return err
}

func buildOutageEmbed(title, description string, color int) *discordgo.MessageEmbed {
	return &discordgo.MessageEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
}

func (b *Bridge) deleteWebhookMessage(messageID string) error {
	webhookID, webhookToken := parseWebhookURL(b.cfg.DiscordWebhookURL)
	return b.session.WebhookMessageDelete(webhookID, webhookToken, messageID)
}

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

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", hours, minutes)
}
