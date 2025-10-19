package cookie

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func (r *RefreshService) retryWithFreshCSRF() (string, error) {
	loginURL := fmt.Sprintf("https://%s/login/", r.domain)
	resp, err := r.client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("failed to refetch login page: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`name="_xfToken" value="([^"]+)"`)
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("csrf retry token not found")
	}
	csrf := string(m[1])
	log.Printf("✅ Retry CSRF token: %.10s...", csrf)

	postURL := fmt.Sprintf("https://%s/login/login", r.domain)
	form := url.Values{
		"login":       {r.username},
		"password":    {r.password},
		"_xfToken":    {csrf},
		"_xfRedirect": {"/"},
	}
	req, _ := http.NewRequest("POST", postURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Referer", loginURL)
	req.Header.Set("Origin", fmt.Sprintf("https://%s", r.domain))
	req.Header.Set("X-XF-Token", csrf)
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	resp2, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("retry POST failed: %v", err)
	}
	defer resp2.Body.Close()

	var reader io.ReadCloser
	if resp2.Header.Get("Content-Encoding") == "gzip" {
		gz, ge := gzip.NewReader(resp2.Body)
		if ge == nil {
			reader = gz
			defer gz.Close()
		} else {
			reader = io.NopCloser(resp2.Body)
		}
	} else {
		reader = io.NopCloser(resp2.Body)
	}
	b, _ := io.ReadAll(reader)
	if strings.Contains(string(b), `data-logged-in="true"`) {
		log.Println("✅ Retry indicates logged in successfully")
	}

	cookieURL, _ := url.Parse(fmt.Sprintf("https://%s/", r.domain))
	for _, c := range r.client.Jar.Cookies(cookieURL) {
		if c.Name == "xf_user" {
			log.Printf("✅ Successfully fetched fresh cookie with xf_user: %.12s...", c.Value)
			// Rebuild cookie header with known-good set (reuse attemptFetchCookie’s logic if you want)
			return "xf_user=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("retry still missing xf_user cookie")
}
