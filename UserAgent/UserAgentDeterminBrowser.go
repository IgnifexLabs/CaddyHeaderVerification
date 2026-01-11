package useragent

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type BrowserKind string

const (
	BrowserChrome  BrowserKind = "chrome"
	BrowserEdge    BrowserKind = "edge"
	BrowserFirefox BrowserKind = "firefox"
	BrowserBrave   BrowserKind = "brave"
	BrowserUnknown BrowserKind = "unknown"
)

type HeaderCheckResult struct {
	Browser    BrowserKind
	HeaderLen  int
	WithinSpec bool
	Reason     string
}

var (
	reFirefox = regexp.MustCompile(`Firefox/\d+\.\d+`)
	reChrome  = regexp.MustCompile(`Chrome/\d+\.\d+`)
	reEdge    = regexp.MustCompile(`Edg/\d+\.\d+`)
)

// DetectBrowser determines the browser using User-Agent and Sec-CH-UA hints.
// Order:
//  1. Firefox (UA)
//  2. Edge (UA: Edg/…)
//  3. Brave (Chrome-like UA, but Sec-Ch-Ua or Sec-Ch-Ua-Full-Version-List contains "Brave")
//  4. Chrome (UA)
//  5. Unknown
func DetectBrowser(h http.Header) BrowserKind {
	ua := h.Get("User-Agent")
	secChUa := h.Get("Sec-Ch-Ua")
	secChFullList := h.Get("Sec-Ch-Ua-Full-Version-List")

	uaLower := strings.ToLower(ua)
	secChLower := strings.ToLower(secChUa + " " + secChFullList)

	// 1) Firefox
	if reFirefox.MatchString(ua) {
		TeHttpheader := h.Get("Te")
		if TeHttpheader == "trailers" {
			return BrowserFirefox
		}
	}

	// 2) Edge
	if reEdge.MatchString(ua) || strings.Contains(uaLower, "edg/") {
		return BrowserEdge
	}

	// 3) Brave: look for "Brave" in client hints
	if strings.Contains(secChLower, "brave") {
		return BrowserBrave
	}

	// 4) Chrome
	if reChrome.MatchString(ua) {
		return BrowserChrome
	}

	return BrowserUnknown
}

// ValidateHeaderLength enforces min/max header count per browser.
//
// Fill in *your actual* numbers here. Example:
//
//	Brave:  min 10, max 14
//	Chrome: min 25, max 35
//	Edge:   min 23, max 40
//	Firefox:min  8, max 20
func ValidateHeaderLength(h http.Header) HeaderCheckResult {
	browser := DetectBrowser(h)
	headerLen := len(h)

	var min, max int
	switch browser {
	case BrowserBrave:
		min, max = 16, 23
	case BrowserChrome:
		min, max = 27, 32
	case BrowserEdge:
		min, max = 25, 30
	case BrowserFirefox:
		min, max = 9, 13
	default:
		// No constraints for unknown -> always "ok"
		return HeaderCheckResult{
			Browser:    browser,
			HeaderLen:  headerLen,
			WithinSpec: true,
			Reason:     "no constraints for unknown browser",
		}
	}

	if headerLen < min {
		return HeaderCheckResult{
			Browser:    browser,
			HeaderLen:  headerLen,
			WithinSpec: false,
			Reason:     fmt.Sprintf("too few headers: %d < %d", headerLen, min),
		}
	}
	if headerLen > max {
		return HeaderCheckResult{
			Browser:    browser,
			HeaderLen:  headerLen,
			WithinSpec: false,
			Reason:     fmt.Sprintf("too many headers: %d > %d", headerLen, max),
		}
	}

	return HeaderCheckResult{
		Browser:    browser,
		HeaderLen:  headerLen,
		WithinSpec: true,
		Reason:     "within expected range",
	}
}
