package cookie

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (r *RefreshService) getClearanceToken() (string, error) {
	baseURL := fmt.Sprintf("https://%s/", r.domain)
	req, _ := http.NewRequest("GET", baseURL, nil)
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<html[^>]*id=["']sssg["'][^>]*data-sssg-challenge=["']([^"']+)["'][^>]*data-sssg-difficulty=["'](\d+)["']`),
		regexp.MustCompile(`<html[^>]*id=["']sssg["'][^>]*data-sssg-difficulty=["'](\d+)["'][^>]*data-sssg-challenge=["']([^"']+)["']`),
		regexp.MustCompile(`data-sssg-challenge=["']([^"']+)["'][^>]*data-sssg-difficulty=["'](\d+)["']`),
	}
	var salt string
	var difficulty int
	found := false
	for i, p := range patterns {
		if m := p.FindStringSubmatch(string(body)); len(m) >= 3 {
			if i == 1 {
				difficulty, _ = strconv.Atoi(m[1])
				salt = m[2]
			} else {
				salt = m[1]
				difficulty, _ = strconv.Atoi(m[2])
			}
			found = true
			break
		}
	}
	if !found || difficulty == 0 || salt == "" {
		return "", nil
	}

	log.Printf("Solving KiwiFlare challenge (difficulty=%d)", difficulty)
	time.Sleep(time.Duration(500+rand.Intn(750)) * time.Millisecond)

	nonce, err := r.solvePoW(salt, difficulty)
	if err != nil {
		return "", err
	}

	time.Sleep(time.Duration(700+rand.Intn(900)) * time.Millisecond)

	submitURL := fmt.Sprintf("https://%s/.sssg/api/answer", r.domain)
	form := url.Values{"a": {salt}, "b": {nonce}}
	post, _ := http.NewRequest("POST", submitURL, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("User-Agent", randomUserAgent())
	post.Header.Set("Origin", baseURL)
	post.Header.Set("Referer", baseURL)

	resp2, err := r.client.Do(post)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()

	var result map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&result)

	time.Sleep(time.Duration(1200+rand.Intn(800)) * time.Millisecond)

	cookieURL, _ := url.Parse(baseURL)
	for _, c := range r.client.Jar.Cookies(cookieURL) {
		if c.Name == "sssg_clearance" {
			log.Printf("✅ KiwiFlare clearance cookie confirmed: %s...", c.Value[:min(10, len(c.Value))])
			return c.Value, nil
		}
	}
	if v, ok := result["auth"].(string); ok && v != "" {
		r.client.Jar.SetCookies(cookieURL, []*http.Cookie{{
			Name:   "sssg_clearance",
			Value:  v,
			Path:   "/",
			Domain: r.domain,
		}})
		return v, nil
	}
	return "", fmt.Errorf("clearance cookie missing after solve")
}

func (r *RefreshService) solvePoW(salt string, difficulty int) (string, error) {
	start := time.Now()
	bytes := difficulty / 8
	bits := difficulty % 8

	for nonce := rand.Int63(); ; nonce++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s%d", salt, nonce)))
		ok := true
		for i := 0; i < bytes; i++ {
			if sum[i] != 0 {
				ok = false
				break
			}
		}
		if ok && bits > 0 && bytes < len(sum) {
			mask := byte(0xFF << (8 - bits))
			if sum[bytes]&mask != 0 {
				ok = false
			}
		}
		if ok {
			delay := time.Duration(2+rand.Intn(3))*time.Second - time.Since(start)
			if delay > 0 {
				time.Sleep(delay)
			}
			return fmt.Sprintf("%d", nonce), nil
		}
	}
}
