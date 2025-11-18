package media

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	litterboxTTL       = "72h"
	litterboxEndpoint  = "https://litterbox.catbox.moe/resources/internals/api.php"
	defaultHTTPTimeout = 60 * time.Second
)

type LitterboxService struct {
	client *http.Client
}

func (s *LitterboxService) Name() string { return DefaultService }

func (s *LitterboxService) Upload(ctx context.Context, attachment *discordgo.MessageAttachment) (string, int, error) {
	client := s.client
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if client.Timeout == 0 {
		client.Timeout = defaultHTTPTimeout
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, attachment.URL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("reqtype", "fileupload")
	_ = writer.WriteField("time", litterboxTTL)
	part, _ := writer.CreateFormFile("fileToUpload", attachment.Filename)
	_, _ = part.Write(data)
	_ = writer.Close()

	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, litterboxEndpoint, body)
	if err != nil {
		return "", 0, err
	}
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())

	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		return "", 0, err
	}
	defer uploadResp.Body.Close()
	if uploadResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(uploadResp.Body)
		reason := strings.TrimSpace(string(bodyBytes))
		if reason != "" {
			return "", uploadResp.StatusCode, fmt.Errorf("Litterbox returned HTTP %d: %s", uploadResp.StatusCode, reason)
		}
		return "", uploadResp.StatusCode, fmt.Errorf("Litterbox returned HTTP %d", uploadResp.StatusCode)
	}
	out, _ := io.ReadAll(uploadResp.Body)
	url := strings.TrimSpace(string(out))
	return url, uploadResp.StatusCode, nil
}
