package utils

import (
	"regexp"
	"strings"
)

// Pre-compiled regex patterns (Go 1.19 compatible)
var (
	imgPattern      = regexp.MustCompile(`(?i)\[img\](.*?)\[/img\]`)
	videoPattern    = regexp.MustCompile(`(?i)\[video\](.*?)\[/video\]`)
	urlPattern      = regexp.MustCompile(`(?i)\[url=(.*?)\](.*?)\[/url\]`)
	urlSimplePattern = regexp.MustCompile(`(?i)\[url\](.*?)\[/url\]`)
	boldPattern     = regexp.MustCompile(`(?i)\[(?:b|strong)\](.*?)\[/\s*(?:b|strong)\]`)
	italicPattern   = regexp.MustCompile(`(?i)\[(?:i|em)\](.*?)\[/\s*(?:i|em)\]`)
	underlinePattern = regexp.MustCompile(`(?i)\[u\](.*?)\[/\s*u\]`)
	strikePattern   = regexp.MustCompile(`(?i)\[(?:s|strike)\](.*?)\[/\s*(?:s|strike)\]`)
	codePattern     = regexp.MustCompile(`(?i)\[code\](.*?)\[/code\]`)
	codeBlockPattern = regexp.MustCompile(`(?i)\[(?:php|plain|code=\w+)\](.*?)\[/(?:php|plain|code)\]`)
	quotePattern    = regexp.MustCompile(`(?i)\[quote\](.*?)\[/quote\]`)
	spoilerPattern  = regexp.MustCompile(`(?i)\[spoiler\](.*?)\[/spoiler\]`)
	colorSizePattern = regexp.MustCompile(`(?i)\[(?:color|size)=.*?\](.*?)\[/\s*(?:color|size)\]`)
	listItemPattern = regexp.MustCompile(`(?m)^\[\*\]\s*`)
	listTagPattern  = regexp.MustCompile(`(?i)\[/?list\]`)
	genericTagPattern = regexp.MustCompile(`\[/?[A-Za-z0-9\-=_]+\]`)
	httpPattern     = regexp.MustCompile(`(?i)^https?://`)
)

func BBCodeToMarkdown(text string) string {
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	text = imgPattern.ReplaceAllString(text, "$1")
	text = videoPattern.ReplaceAllString(text, "$1")

	text = urlPattern.ReplaceAllStringFunc(text, func(match string) string {
		parts := urlPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		link := strings.TrimSpace(parts[1])
		txt := strings.TrimSpace(parts[2])
		if httpPattern.MatchString(txt) {
			return txt
		}
		return "[" + txt + "](" + link + ")"
	})

	text = urlSimplePattern.ReplaceAllString(text, "$1")
	text = boldPattern.ReplaceAllString(text, "**$1**")
	text = italicPattern.ReplaceAllString(text, "*$1*")
	text = underlinePattern.ReplaceAllString(text, "__$1__")
	text = strikePattern.ReplaceAllString(text, "~~$1~~")
	text = codePattern.ReplaceAllString(text, "`$1`")
	text = codeBlockPattern.ReplaceAllString(text, "```$1```")

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

	text = spoilerPattern.ReplaceAllString(text, "||$1||")
	text = colorSizePattern.ReplaceAllString(text, "$1")
	text = listItemPattern.ReplaceAllString(text, "• ")
	text = listTagPattern.ReplaceAllString(text, "")
	text = genericTagPattern.ReplaceAllString(text, "")

	return strings.TrimSpace(text)
}