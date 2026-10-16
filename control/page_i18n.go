package control

import (
	"fmt"
	"net/http"
	"strings"
)

// 独立授权页保留语言和配色偏好；用户中心本身只由 Web 应用渲染。
const (
	consoleLangCookie   = "xunara_lang"
	consoleAccentCookie = "xunara_accent"

	consoleDefaultLang   = "en"
	consoleDefaultAccent = "blue"
)

// consoleLangs are the selectable languages; consoleAccents the selectable
// accent palettes (the token blocks live in the console stylesheet).
var (
	consoleLangs   = map[string]bool{"zh": true, "en": true}
	consoleAccents = map[string]bool{"blue": true, "teal": true}
)

// consoleDict is one language: text maps a trimmed text node or attribute
// value to its translation, block maps the trimmed inner markup of a <p> to a
// translated paragraph (used for prose that contains inline <code>/<em>).
type consoleDict struct {
	text  map[string]string
	block map[string]string
	// prefix maps a leading English fragment to Chinese; the remainder of the
	// string is appended unchanged, which covers sentences that embed a
	// runtime value (an error, a file name, a count).
	prefix map[string]string
}

// consoleTranslations holds one dictionary per language keyed by message id.
var consoleTranslations = map[string]consoleDict{"zh": {
	text:   mergeText(consoleZH, consoleZHPublic),
	block:  mergeText(consoleZHBlock, consoleZHPublicBlock),
	prefix: consoleZHPrefix,
}}

// mergeText combines two message tables. Later entries win, which lets the
// hand-written public-page copy refine a generated console string without
// editing the generated file.
func mergeText(tables ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, table := range tables {
		for key, value := range table {
			merged[key] = value
		}
	}
	return merged
}

// consoleLangFromRequest resolves the UI language: the preference cookie the
// operator set in the console wins, otherwise the browser's Accept-Language
// decides between the two supported languages, and an absent or unhelpful
// header keeps the console in English.
func consoleLangFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(consoleLangCookie); err == nil && consoleLangs[cookie.Value] {
		return cookie.Value
	}
	return acceptLanguage(consoleLangs, r.Header.Get("Accept-Language"))
}

// acceptLanguage returns the language a browser asks for, restricted to the
// supported set: "zh" wins when it is preferred over "en", and the fallback
// is English. Matching is on the primary subtag ("zh-CN" matches "zh"), the
// way browsers and RFC 9110 define it.
func acceptLanguage(supported map[string]bool, header string) string {
	best, bestQuality := "", -1.0
	for _, part := range strings.Split(header, ",") {
		tag, quality := strings.TrimSpace(part), 1.0
		if semi := strings.IndexByte(tag, ';'); semi >= 0 {
			params := tag[semi+1:]
			tag = strings.TrimSpace(tag[:semi])
			if q := strings.Index(params, "q="); q >= 0 {
				quality = parseQuality(params[q+2:])
			}
		}
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || tag == "*" {
			continue
		}
		primary := tag
		if dash := strings.IndexByte(primary, '-'); dash >= 0 {
			primary = primary[:dash]
		}
		if !supported[primary] {
			continue
		}
		if quality > bestQuality {
			best, bestQuality = primary, quality
		}
	}
	if best == "" {
		return consoleDefaultLang
	}
	return best
}

// parseQuality reads the q value of one Accept-Language entry.
func parseQuality(value string) float64 {
	value = strings.TrimSpace(value)
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = strings.TrimSpace(value[:semi])
	}
	var quality float64
	if _, err := fmt.Sscanf(value, "%g", &quality); err != nil {
		return 1.0
	}
	if quality < 0 {
		return 0
	}
	if quality > 1 {
		return 1
	}
	return quality
}

// consoleAccentFromRequest resolves the accent palette from the cookie.
func consoleAccentFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(consoleAccentCookie); err == nil && consoleAccents[cookie.Value] {
		return cookie.Value
	}
	return consoleDefaultAccent
}

// translator returns the T template function for one language: it looks the
// message id up in the dictionary and formats it when arguments are given.
// Unknown ids render as the English source text.
func translator(lang string) func(string, ...any) string {
	dict := consoleTranslations[lang].text
	return func(key string, args ...any) string {
		text := key
		if translated, ok := dict[key]; ok {
			text = translated
		}
		if len(args) == 0 {
			return text
		}
		return fmt.Sprintf(text, args...)
	}
}

// handlePagePrefs 只修改非敏感的页面偏好，不能跳到站外或恢复旧控制台。
func (s *Server) handlePagePrefs(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "/" {
		returnTo = "/dashboard"
	}
	if lang := r.URL.Query().Get("lang"); lang != "" {
		if !consoleLangs[lang] {
			lang = consoleDefaultLang
		}
		s.setPrefCookie(w, consoleLangCookie, lang)
	}
	if accent := r.URL.Query().Get("accent"); accent != "" {
		if !consoleAccents[accent] {
			accent = consoleDefaultAccent
		}
		s.setPrefCookie(w, consoleAccentCookie, accent)
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// setPrefCookie stores one long-lived preference. The values are not secrets,
// but they are still scoped and SameSite=Lax like the session cookie.
func (s *Server) setPrefCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
	})
}

// consoleNavItem is one console section in the sidebar.
