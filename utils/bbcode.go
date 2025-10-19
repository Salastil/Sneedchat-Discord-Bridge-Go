package utils

import (
	"regexp"
	"strings"
)

func BBCodeToMarkdown(text string) string {
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	text = regexp.MustCompile(`(?i)\[img\](.*?)\[/img\]`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`(?i)\[video\](.*?)\[/video\]`).ReplaceAllString(text, "$1")

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
		return "[" + txt + "](" + link + ")"
	})

	text = regexp.MustCompile(`(?i)\[url\](.*?)\[/url\]`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`(?i)\[(?:b|strong)\](.*?)\[/\s*(?:b|strong)\]`).ReplaceAllString(text, "**$1**")
	text = regexp.MustCompile(`(?i)\[(?:i|em)\](.*?)\[/\s*(?:i|em)\]`).ReplaceAllString(text, "*$1*")
	text = regexp.MustCompile(`(?i)\[u\](.*?)\[/\s*u\]`).ReplaceAllString(text, "__$1__")
	text = regexp.MustCompile(`(?i)\[(?:s|strike)\](.*?)\[/\s*(?:s|strike)\]`).ReplaceAllString(text, "~~$1~~")
	text = regexp.MustCompile(`(?i)\[code\](.*?)\[/code\]`).ReplaceAllString(text, "`$1`")
	text = regexp.MustCompile(`(?i)\[(?:php|plain|code=\w+)\](.*?)\[/(?:php|plain|code)\]`).ReplaceAllString(text, "```$1```")

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

	text = regexp.MustCompile(`(?i)\[spoiler\](.*?)\[/spoiler\]`).ReplaceAllString(text, "||$1||")
	text = regexp.MustCompile(`(?i)\[(?:color|size)=.*?\](.*?)\[/\s*(?:color|size)\]`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`(?m)^\[\*\]\s*`).ReplaceAllString(text, "• ")
	text = regexp.MustCompile(`(?i)\[/?list\]`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`\[/?[A-Za-z0-9\-=_]+\]`).ReplaceAllString(text, "")

	return strings.TrimSpace(text)
}
