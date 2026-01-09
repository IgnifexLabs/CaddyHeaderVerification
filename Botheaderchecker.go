package headerchecker

import (
	"net/http"
	"regexp"
	"strings"

	"go.uber.org/zap"

	useragent "github.com/beserkerbob/HeaderChecker/UserAgent"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Ensure the module implements caddyhttp.MiddlewareHandler
var _ caddyhttp.MiddlewareHandler = (*HeaderChecker)(nil)

func init() {
	caddy.RegisterModule(HeaderChecker{})
	httpcaddyfile.RegisterHandlerDirective("headerchecker", parseCaddyfile)
}

// HeaderChecker checks various UA-related headers and compares their versions.
type HeaderChecker struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (HeaderChecker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.headerchecker",
		New: func() caddy.Module { return new(HeaderChecker) },
	}
}
func (h *HeaderChecker) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// No arguments needed, just consume the directive
	for d.Next() {
	}
	return nil
}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var hc HeaderChecker
	err := hc.UnmarshalCaddyfile(h.Dispenser)
	return hc, err
}

// Provision is called by Caddy to set up the module.

func (h *HeaderChecker) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h) // Module-specific logger
	return nil
}

var (
	// 3-digit main version (e.g. 144 from 144.0.0.0)
	reThreeDigits = regexp.MustCompile(`\b([0-9]{3})\b`)

	// Chrome/144.0.0.0 → 144
	reChromeFromUA = regexp.MustCompile(`Chrome/([0-9]{3})`)

	// "Google Chrome";v="144" or "Microsoft Edge";v="144"
	reBrandVersion = regexp.MustCompile(`(?:Google Chrome|Microsoft Edge)"?;v="([0-9]{3})`)
)

// helper: extract first 3-digit group
func firstThreeDigits(s string) string {
	m := reThreeDigits.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// helper: Chrome version from UA
func chromeFromUA(ua string) string {
	m := reChromeFromUA.FindStringSubmatch(ua)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// helper: version from Sec-CH headers for Chrome/Edge
func brandVersion(s string) string {
	m := reBrandVersion.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}
func (h HeaderChecker) logRequest(r *http.Request) {
	if h.logger == nil {
		return
	}

	// Convert headers to a map[string][]string, which Zap can render nicely
	headers := map[string][]string{}
	for k, v := range r.Header {
		// copy slice to avoid aliasing, optional
		copied := make([]string, len(v))
		copy(copied, v)
		headers[k] = copied
	}

	h.logger.Info("incoming HTTP request",
		zap.String("method", r.Method),
		zap.String("scheme", r.URL.Scheme),
		zap.String("host", r.Host),
		zap.String("path", r.URL.Path),
		zap.String("raw_query", r.URL.RawQuery),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("proto", r.Proto),
		zap.Any("headers", headers),
	)
}

// isImageRequest returns true if the request appears to be for an image,
// either based on the URL or on the Accept header.
func isImageRequest(path, accept, contentType string) bool {
	// Check file extension in the URL
	lowerPath := strings.ToLower(path)
	lowerCT := strings.ToLower(contentType)

	if strings.HasSuffix(lowerPath, ".ico") ||
		strings.HasSuffix(lowerPath, ".png") ||
		strings.HasSuffix(lowerPath, ".jpg") ||
		strings.HasSuffix(lowerPath, ".jpeg") ||
		strings.HasSuffix(lowerPath, ".gif") ||
		strings.HasSuffix(lowerPath, ".webp") ||
		strings.HasSuffix(lowerPath, ".avif") {
		return true
	}

	// Content-Type is explicitly an image (including image/jpeg)
	if strings.HasPrefix(lowerCT, "image/") {
		return true
	}

	return false
}

func (h HeaderChecker) validateChromeAcceptHeader(r *http.Request) bool {
	var reChromeRange = regexp.MustCompile(`Chrome/(13[1-9]|1[4-9][0-9])\.0`)
	const targetAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	const targetAcceptBrave = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
	const targetAcceptImage = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	const targetAcceptImageBrave = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"

	secChUaFullVersionList := r.Header.Get("Sec-Ch-Ua-Full-Version-List")
	secChUa := r.Header.Get("Sec-Ch-Ua")
	accept := r.Header.Get("Accept")
	ua := r.Header.Get("User-Agent")
	// Version range check via regex only
	if !reChromeRange.MatchString(ua) {
		return false
	}

	path := r.URL.Path
	ct := r.Header.Get("Content-Type")

	//Check if the request is for an image
	if isImageRequest(path, accept, ct) {

		if isBraveFromClientHints(secChUa, secChUaFullVersionList) {
			if !strings.EqualFold(accept, targetAcceptImageBrave) {
				if h.logger != nil {
					h.logger.Warn("Brave Accept image header not matching",
						zap.String("Received acceptheader", accept),
						zap.String("target acceptheader", targetAcceptImageBrave),
					)
				}
				return false
			}
		} else if !strings.EqualFold(accept, targetAcceptImage) {
			if h.logger != nil {
				h.logger.Warn("Chrome Accept image header not matching",
					zap.String("Received acceptheader", accept),
					zap.String("target acceptheader", targetAcceptImage),
				)
			}
			return false
		}
		return true
	}
	if isBraveFromClientHints(secChUa, secChUaFullVersionList) {
		if !strings.EqualFold(accept, targetAcceptBrave) {
			if h.logger != nil {
				h.logger.Warn("Brave Accept header not matching",
					zap.String("Received acceptheader", accept),
					zap.String("target acceptheader", targetAcceptBrave),
				)
			}
			return false
		}
	} else if !strings.EqualFold(accept, targetAccept) {
		if h.logger != nil {
			h.logger.Warn("Chrome Accept header not matching",
				zap.String("Received acceptheader", accept),
				zap.String("target acceptheader", targetAccept),
			)
		}
		return false
	}
	if h.logger != nil {
		h.logger.Info("Chrome Accept header good")
	}
	return true

}

func (h HeaderChecker) validateFireFoxAcceptHeader(r *http.Request) bool {
	var reFirefoxRange = regexp.MustCompile(`Firefox/(13[2-9]|1[4-9][0-9])\.0`)
	const targetAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	const targetAcceptImage = "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"

	accept := r.Header.Get("Accept")
	ua := r.Header.Get("User-Agent")
	// Version range check via regex only
	if !reFirefoxRange.MatchString(ua) {
		return false
	}

	path := r.URL.Path
	ct := r.Header.Get("Content-Type")

	//Check if the request is for an image
	if isImageRequest(path, accept, ct) {
		// Case-insensitive Accept match (like grep -i)
		if !strings.EqualFold(accept, targetAcceptImage) {
			if h.logger != nil {
				h.logger.Warn("Firefox Accept image header not matching",
					zap.String("Received acceptheader", accept),
					zap.String("target acceptheader", targetAcceptImage),
				)
			}
			return false
		}
		return true
	}

	// Case-insensitive Accept match (like grep -i)
	if !strings.EqualFold(accept, targetAccept) {
		if h.logger != nil {
			h.logger.Warn("Firefox Accept header not matching",
				zap.String("Received acceptheader", accept),
				zap.String("target acceptheader", targetAccept),
			)
		}
		return false
	}
	if h.logger != nil {
		h.logger.Info("Firefox Accept header good")
	}
	return true

}

func validateAcceptHeader(acceptHeaderValues []string) bool {
	// Check if the accept header values indicate it is a bot by accepting everything
	if len(acceptHeaderValues) == 1 && acceptHeaderValues[0] == "*/*" {
		return false
	}
	return true
}

func isBraveFromClientHints(secChUa, secChUaFullVersionList string) bool {
	// Very simple heuristic: look for "Brave" in either header.
	// Adjust if you want case-insensitive matching or stricter parsing.
	ClientHintUserAgent := strings.ToLower(secChUa)
	ClienthintFullVersionList := strings.ToLower(secChUaFullVersionList)
	if strings.Contains(ClientHintUserAgent, "brave") && strings.Contains(ClienthintFullVersionList, "brave") {
		return true
	}

	return false
}

func (h HeaderChecker) crossReferenceClientHintHeaders(r *http.Request) bool {
	secChUaFullVersion := r.Header.Get("Sec-Ch-Ua-Full-Version")
	secChUaFullVersionList := r.Header.Get("Sec-Ch-Ua-Full-Version-List")
	userAgent := r.Header.Get("User-Agent")
	secChUa := r.Header.Get("Sec-Ch-Ua")

	mainVerSecFull := firstThreeDigits(secChUaFullVersion)
	mainVerSecFullList := brandVersion(secChUaFullVersionList)
	mainVerUA := chromeFromUA(userAgent)
	mainVerSecUa := brandVersion(secChUa)

	// Brave exception:
	// If all "main version" values are empty, but Sec-Ch-Ua or
	// Sec-Ch-Ua-Full-Version-List clearly indicate Brave, we accept it.
	if mainVerSecFull == "" &&
		isBraveFromClientHints(secChUa, secChUaFullVersionList) {

		if h.logger != nil {
			h.logger.Info("Header versions empty but Brave detected, accepting",
				zap.String("Sec-Ch-Ua", secChUa),
				zap.String("Sec-Ch-Ua-Full-Version", secChUaFullVersion),
				zap.String("Sec-Ch-Ua-Full-Version-List", secChUaFullVersionList),
				zap.String("User-Agent", userAgent),
			)
		}
		return true
	}

	// Compare versions similar to your shell script logic
	if mainVerSecFull == "" || mainVerSecFullList == "" || mainVerUA == "" || mainVerSecUa == "" ||
		mainVerSecFull != mainVerSecFullList ||
		mainVerSecFull != mainVerUA ||
		mainVerSecFull != mainVerSecUa {

		if h.logger != nil {
			h.logger.Warn("Header version mismatch",
				zap.String("Sec-Ch-Ua-Full-Version", secChUaFullVersion),
				zap.String("Sec-Ch-Ua-Full-Version-main", mainVerSecFull),
				zap.String("Sec-Ch-Ua-Full-Version-List", secChUaFullVersionList),
				zap.String("Sec-Ch-Ua-Full-Version-List-main", mainVerSecFullList),
				zap.String("User-Agent", userAgent),
				zap.String("User-Agent-Chrome-main", mainVerUA),
				zap.String("Sec-Ch-Ua", secChUa),
				zap.String("Sec-Ch-Ua-main", mainVerSecUa),
			)
		}

		return false
	} else {
		if h.logger != nil {
			h.logger.Info("Header versions match",
				zap.String("mainVersion", mainVerSecFull),
			)
		}
		return true
	}
}

// The following function checks if there is a wrong implementation based on the fact that Linux
// has a hard implementation of X11; Linux x86_64
func (h HeaderChecker) ValidateSecChUaPlatformLinux(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// Exclude the accepted default value for desktop Linux browsers: "X11; Linux x86_64"
	if strings.Contains(ua, "X11; Linux x86_64") {
		return true
	}

	// If we reach this point: Linux platform, but not a typical X11 desktop UA:
	// classify as bot.
	return false

}

const DevtoolsPath = "/.well-known/appspecific/com.chrome.devtools.json"

func IsDevtoolsPath(r *http.Request) bool {
	return r.URL.Path == DevtoolsPath
}

// memSetNot8 returns true if Sec-CH-Device-Memory is present and not "8".
func CheckSecCHDeviceMemoryequalto8(r *http.Request) bool {
	val := r.Header.Get("Sec-Ch-Device-Memory")
	secChUaFullVersionList := r.Header.Get("Sec-Ch-Ua-Full-Version-List")
	secChUa := r.Header.Get("Sec-Ch-Ua")
	// Equivalent of `header_regexp ... ^.+$` → header must be non-empty
	if strings.TrimSpace(val) == "" {
		if isBraveFromClientHints(secChUa, secChUaFullVersionList) {
			return true
		}
		return false
	}

	// Equivalent of `not { header Sec-CH-Device-Memory 8 }`
	if val != "8" {
		return false
	}

	return true
}

// ServeHTTP inspects the headers and then calls the next handler.
func (h HeaderChecker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.logRequest(r)
	// Simple “is this Firefox at all?” check
	var reFirefox = regexp.MustCompile(`Firefox/\d+\.\d+`)
	var reChrome = regexp.MustCompile(`Chrome/\d+\.\d+`)

	if IsDevtoolsPath(r) {
		if h.logger != nil {
			h.logger.Warn("Someone is using the devtools block request",
				zap.String("Pat that was excest", r.URL.Path),
			)
		}
	}

	botdetected := false
	ua := r.Header.Get("User-Agent")
	reduced := useragent.ValidateReduction(ua)
	if useragent.IsOldBrowser(ua) {
		if h.logger != nil {
			h.logger.Warn("request from old browser based on user agent ",
				zap.String("user agent=", ua),
			)
		}
		botdetected = true
	}

	if reduced == false {
		if h.logger != nil {
			h.logger.Warn("User agent reduction error",
				zap.String("user agent=", ua),
			)
		}
		botdetected = true
	}
	if reFirefox.MatchString(ua) {
		if h.validateFireFoxAcceptHeader(r) == false {
			if h.logger != nil {
				h.logger.Warn("error in firefox acceptheader")
			}
			botdetected = true
		}
	}
	if reChrome.MatchString(ua) {
		if CheckSecCHDeviceMemoryequalto8(r) == false {
			if h.logger != nil {
				h.logger.Warn("Memory of device lower then 8 high bot change")
			}
			botdetected = true
		}
		if h.crossReferenceClientHintHeaders(r) == false {
			if h.logger != nil {
				h.logger.Warn("CrossReference Clienthint errors ")
			}
			botdetected = true
		}
		if h.validateChromeAcceptHeader(r) == false {
			if h.logger != nil {
				h.logger.Warn("error in Chrome acceptheader")
			}
			botdetected = true
		}
		secChUaPlatform := r.Header.Get("Sec-Ch-Ua-Platform")
		secChUa := r.Header.Get("Sec-Ch-Ua")
		if useragent.IsBotFromSecChUa(secChUa) {
			if h.logger != nil {
				h.logger.Warn("CLient hint Ua contains bot related data",
					zap.String("user agent=", secChUa),
				)
			}
			botdetected = true
		}
		if strings.Contains(strings.ToLower(secChUaPlatform), "linux") {
			if h.ValidateSecChUaPlatformLinux(r) == false {
				if h.logger != nil {
					h.logger.Warn("CLient hint platform linux contains an error",
						zap.String("SecCHuser agent=", secChUa))
				}
				botdetected = true
			}
		}
	}
	if validateAcceptHeader(r.Header.Values("Accept")) && botdetected == false {
		w.Header().Set("SecureHeader", "true")
	} else {
		w.Header().Set("SecureHeader", "false")
	}
	return next.ServeHTTP(w, r)
}
