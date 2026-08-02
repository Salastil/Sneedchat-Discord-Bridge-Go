package utils

import (
	"regexp"
	"strings"
)

// Pre-compiled regex patterns (Go 1.19 compatible)
var (
	brPattern        = regexp.MustCompile(`(?i)\[br\s*/?\]`)
	imgPattern       = regexp.MustCompile(`(?i)\[img\](.*?)\[/img\]`)
	videoPattern     = regexp.MustCompile(`(?i)\[video\](.*?)\[/video\]`)
	urlPattern       = regexp.MustCompile(`(?i)\[url=(.*?)\](.*?)\[/url\]`)
	urlSimplePattern = regexp.MustCompile(`(?i)\[url\](.*?)\[/url\]`)
	boldPattern      = regexp.MustCompile(`(?i)\[(?:b|strong)\](.*?)\[/\s*(?:b|strong)\]`)
	italicPattern    = regexp.MustCompile(`(?i)\[(?:i|em)\](.*?)\[/\s*(?:i|em)\]`)
	underlinePattern = regexp.MustCompile(`(?i)\[u\](.*?)\[/\s*u\]`)
	strikePattern    = regexp.MustCompile(`(?i)\[(?:s|strike)\](.*?)\[/\s*(?:s|strike)\]`)
	codePattern      = regexp.MustCompile(`(?i)\[code\](.*?)\[/code\]`)
	codeBlockPattern = regexp.MustCompile(`(?i)\[(?:php|plain|code=\w+)\](.*?)\[/(?:php|plain|code)\]`)
	quotePattern     = regexp.MustCompile(`(?i)\[quote\](.*?)\[/quote\]`)
	// spoilerPattern handles well-formed [spoiler] / [spoiler="Label"] pairs.
	// spoilerOpenPattern is a fallback for Sneedchat's spoiler shorthand,
	// which is sometimes sent without a closing [/spoiler] tag (the site's
	// own HTML rendering treats the spoiler as running to the end of the
	// message in that case, so we mirror that here). Both just unwrap the
	// tag rather than converting to Discord's ||spoiler|| syntax, since
	// wrapping a raw image/link URL in || prevents Discord from unfurling
	// it into an embed.
	spoilerPattern     = regexp.MustCompile(`(?is)\[spoiler(?:=(?:"[^"]*"|'[^']*'|[^\]]*))?\](.*?)\[/spoiler\]`)
	spoilerOpenPattern = regexp.MustCompile(`(?is)\[spoiler(?:=(?:"[^"]*"|'[^']*'|[^\]]*))?\](.*)$`)
	colorSizePattern   = regexp.MustCompile(`(?i)\[(?:color|size)=.*?\](.*?)\[/\s*(?:color|size)\]`)
	listItemPattern    = regexp.MustCompile(`(?m)^\[\*\]\s*`)
	listTagPattern     = regexp.MustCompile(`(?i)\[/?list\]`)
	genericTagPattern  = regexp.MustCompile(`\[/?[A-Za-z0-9\-=_]+\]`)
	httpPattern        = regexp.MustCompile(`(?i)^https?://`)
	blankLinesPattern  = regexp.MustCompile(`\n{3,}`)
)

func BBCodeToMarkdown(text string) string {
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = brPattern.ReplaceAllString(text, "\n")

	// Each image gets its own line so consecutive [img] tags don't collapse
	// into one unparseable, unembeddable URL when sent to Discord.
	text = imgPattern.ReplaceAllString(text, "$1\n")
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

	text = spoilerPattern.ReplaceAllString(text, "$1")
	text = spoilerOpenPattern.ReplaceAllString(text, "$1")
	text = colorSizePattern.ReplaceAllString(text, "$1")
	text = listItemPattern.ReplaceAllString(text, "• ")
	text = listTagPattern.ReplaceAllString(text, "")
	text = stripGenericTags(text)
	text = blankLinesPattern.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text)
}

// stripGenericTags removes leftover/unhandled BBCode tags. It skips matches
// immediately followed by "(", since those are markdown link text (e.g.
// "[Xcancel](https://...)") produced by the url/img conversions above, not
// unhandled BBCode — a bare genericTagPattern replace would otherwise eat
// the link text of any single-word link.
func stripGenericTags(text string) string {
	idxs := genericTagPattern.FindAllStringIndex(text, -1)
	if idxs == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range idxs {
		start, end := m[0], m[1]
		if end < len(text) && text[end] == '(' {
			continue
		}
		b.WriteString(text[last:start])
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}
