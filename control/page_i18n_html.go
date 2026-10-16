package control

import (
	"html"
	"regexp"
	"strings"
)

// 独立授权页复用本地化器，不依赖已退役的内嵌控制台。
// The standalone templates stay English-only: the English text doubles as the
// message id, so a page that is not translated yet renders the English text
// instead of a blank or a key. Translation itself happens after rendering,
// which keeps every page template free of translation bookkeeping and covers
// the shared shell, the console pages and the sign-in/approval pages with one
// code path (spec section 51).
//
// localizeHTML(dict, page) rewrites visible strings only:
//
//   - whole <p> elements whose inner markup has a block translation, so prose
//     with inline <code>/<em> keeps a natural sentence in both languages;
//   - text nodes, trimmed before lookup, so table cells, headings, labels,
//     buttons and status words translate without touching surrounding markup;
//   - placeholder, title, aria-label and alt attribute values.
//
// Content marked with the standard HTML attribute translate="no" is copied
// verbatim: the console prints runtime data (login names, hostnames) that must
// never be mistranslated just because it happens to read like UI copy.
//
// It never enters <script>, <style>, <code>, <pre> or <title> content, so
// code samples, secrets printed once, and the raw JS stay byte-identical. An
// untranslated string is left alone; nothing is ever removed.

// translateHTML returns the page in the request language, or the page
// unchanged when the language has no dictionary.
func translateHTML(lang, page string) string {
	return localizeHTML(consoleTranslations[lang], page)
}

// localizeHTML rewrites one rendered page with one dictionary.
func localizeHTML(dict consoleDict, page string) string {
	if len(page) == 0 || (len(dict.text) == 0 && len(dict.block) == 0 && len(dict.prefix) == 0) {
		return page
	}
	var b strings.Builder
	b.Grow(len(page))
	loc := localizer{dict: dict, out: &b}
	loc.run(page)
	return b.String()
}

// consoleSkipped lists elements whose content is never translated: code
// samples and command lines, the one-time secrets printed inside <pre>, the
// inline stylesheet and script, and the document title (whose English form
// stays stable for bookmarks and browser tabs).
var consoleSkipped = map[string]bool{
	"script": true, "style": true, "code": true, "pre": true, "title": true, "textarea": true,
}

type localizer struct {
	dict consoleDict
	out  *strings.Builder
}

func (l *localizer) run(page string) {
	for i := 0; i < len(page); {
		if page[i] != '<' {
			j := strings.IndexByte(page[i:], '<')
			if j < 0 {
				j = len(page) - i
			}
			l.writeText(page[i : i+j])
			i += j
			continue
		}
		// A skipped element is copied verbatim up to its own close tag, so a
		// script body containing "<" can never be mistaken for markup.
		if name := l.skippedOpenAt(page, i); name != "" {
			end := indexClose(page, i, name)
			l.out.WriteString(page[i:end])
			i = end
			continue
		}
		switch {
		case strings.HasPrefix(page[i:], "<!--"):
			end := indexFrom(page, i+4, "-->")
			l.out.WriteString(page[i:end])
			i = end
		case strings.HasPrefix(page[i:], "<!") || strings.HasPrefix(page[i:], "<?"):
			end := tagEnd(page, i)
			l.out.WriteString(page[i:end])
			i = end
		default:
			i = l.writeTag(page, i)
		}
	}
}

// writeTag copies one element tag, translating a paragraph when it opens a
// block-translated <p>, and translating the visible attributes otherwise.
func (l *localizer) writeTag(page string, start int) int {
	end := tagEnd(page, start)
	if end <= start {
		// Unbalanced markup: copy the rest and stop.
		l.out.WriteString(page[start:])
		return len(page)
	}
	tag := page[start:end]
	name, closing, selfClosing := tagParts(tag)
	if closing || selfClosing || name == "" {
		l.out.WriteString(tag)
		return end
	}
	if name == "p" && len(l.dict.block) > 0 {
		if closeIdx := indexFrom(page, end, "</p>"); closeIdx >= end {
			inner := page[end:closeIdx]
			if translated, ok := lookupBlock(l.dict, inner); ok {
				l.out.WriteString(tag)
				l.out.WriteString(translated)
				l.out.WriteString("</p>")
				return closeIdx + len("</p>")
			}
		}
	}
	l.out.WriteString(localizeAttrs(l.dict, tag))
	return end
}

// writeText copies one text node, replacing it when the trimmed text has a
// translation. Surrounding whitespace is preserved so the layout does not
// change.
func (l *localizer) writeText(text string) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		l.out.WriteString(text)
		return
	}
	translated, ok := l.lookup(html.UnescapeString(trimmed))
	if !ok {
		l.out.WriteString(text)
		return
	}
	start := strings.Index(text, trimmed)
	l.out.WriteString(text[:start])
	l.out.WriteString(html.EscapeString(translated))
	l.out.WriteString(text[start+len(trimmed):])
}

// lookupBlock resolves a paragraph: the templates write it once in English,
// and the renderer escapes entities such as &#39; on the way out, so the
// unescaped form is tried as well.
func lookupBlock(dict consoleDict, inner string) (string, bool) {
	key := strings.TrimSpace(inner)
	if translated, ok := dict.block[key]; ok {
		return translated, true
	}
	if unescaped := html.UnescapeString(key); unescaped != key {
		if translated, ok := dict.block[unescaped]; ok {
			return translated, true
		}
	}
	return "", false
}

// lookup resolves one text node: an exact message id first, then the longest
// leading fragment. A prefix rule keeps the rest of the string, so a sentence
// built around a runtime value still translates.
func (l *localizer) lookup(source string) (string, bool) {
	if translated, ok := l.dict.text[source]; ok {
		return translated, true
	}
	best, bestLen := "", -1
	for prefix := range l.dict.prefix {
		if len(prefix) > bestLen && len(prefix) <= len(source) && strings.HasPrefix(source, prefix) {
			best, bestLen = prefix, len(prefix)
		}
	}
	if bestLen < 0 {
		return "", false
	}
	return l.dict.prefix[best] + strings.TrimLeft(source[len(best):], " "), true
}

func localizeAttrs(dict consoleDict, tag string) string {
	if len(dict.text) == 0 {
		return tag
	}
	return consoleAttrRe.ReplaceAllStringFunc(tag, func(match string) string {
		parts := consoleAttrRe.FindStringSubmatch(match)
		name, value := parts[1], parts[2]
		translated, ok := dict.text[html.UnescapeString(value)]
		if !ok {
			return match
		}
		return name + `="` + html.EscapeString(translated) + `"`
	})
}

// consoleAttrRe matches the attributes whose value is visible text. The
// original attribute name is kept as written.
var consoleAttrRe = regexp.MustCompile(`(?i)\b(placeholder|aria-label|title|alt)="([^"]*)"`)

// skippedOpenAt reports the name of a skipped element starting at start, so
// run() can copy its content verbatim.
func (l *localizer) skippedOpenAt(page string, start int) string {
	end := tagEnd(page, start)
	if end <= start {
		return ""
	}
	name, closing, selfClosing := tagParts(page[start:end])
	if closing || selfClosing || name == "" {
		return ""
	}
	if consoleSkipped[name] {
		return name
	}
	// translate="no" opts an element out of localization; it only applies
	// when the element is closed, or the rest of the page would be swallowed.
	if translateNoRe.MatchString(page[start:end]) && indexFrom(page, end, "</"+name) < len(page) {
		return name
	}
	return ""
}

// translateNoRe matches the HTML attribute that marks runtime data.
var translateNoRe = regexp.MustCompile(`(?i)\btranslate\s*=\s*"no"`)

// tagParts splits a raw tag into its lowercase name and shape.
func tagParts(tag string) (name string, closing, selfClosing bool) {
	body := strings.TrimSuffix(strings.TrimPrefix(tag, "<"), ">")
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "/") {
		closing = true
		body = strings.TrimSpace(body[1:])
	}
	selfClosing = strings.HasSuffix(body, "/")
	body = strings.TrimSuffix(body, "/")
	for i, r := range body {
		if !isTagNameRune(r) {
			name = body[:i]
			break
		}
	}
	if name == "" && body != "" && !strings.ContainsAny(body, " \t\r\n") {
		name = body
	}
	return strings.ToLower(name), closing, selfClosing
}

func isTagNameRune(r rune) bool {
	return r == '-' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// tagEnd returns the index just past the next '>' that is not inside a quoted
// attribute value, or len(page) when the markup is unterminated.
func tagEnd(page string, start int) int {
	quote := byte(0)
	for i := start; i < len(page); i++ {
		c := page[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i + 1
		}
	}
	return len(page)
}

func indexFrom(page string, from int, needle string) int {
	if idx := strings.Index(page[from:], needle); idx >= 0 {
		return from + idx
	}
	return len(page)
}

func indexClose(page string, from int, name string) int {
	idx := indexFrom(page, from, "</"+name)
	if idx >= len(page) {
		return len(page)
	}
	return tagEnd(page, idx)
}
