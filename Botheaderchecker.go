package headerchecker

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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

func isScriptRequest(path, accept, contentType string) bool {
	// Normalize
	lowerPath := strings.ToLower(path)
	lowerCT := strings.ToLower(contentType)
	lowerAccept := strings.ToLower(accept)

	// 1. Check file extension in the URL
	if strings.HasSuffix(lowerPath, ".js") {
		return true
	}

	//Content-Type is explicitly JavaScript
	if strings.HasPrefix(lowerCT, "application/javascript") ||
		strings.HasPrefix(lowerCT, "text/javascript") {
		return true
	}

	// 3. Accept header indicates JavaScript is expected
	if strings.Contains(lowerAccept, "application/javascript") ||
		strings.Contains(lowerAccept, "text/javascript") {
		return true
	}

	return false
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

func (h HeaderChecker) validateSecFetchRequests(r *http.Request) bool {
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	secFetchMode := r.Header.Get("Sec-Fetch-Mode")
	secFetchDest := r.Header.Get("Sec-Fetch-Dest")

	//If one of these headers are empty then it isn't a browser request
	if secFetchSite == "" || secFetchMode == "" || secFetchDest == "" {
		return false
	}
	accept := r.Header.Get("Accept")
	path := r.URL.Path
	ct := r.Header.Get("Content-Type")
	if isImageRequest(path, accept, ct) {
		//these are the standard expected headers for images hosted on your own site
		if secFetchSite == "same-origin" && secFetchMode == "no-cors" && secFetchDest == "image" {
			return true
		} else {
			return false
		}
	} else if isScriptRequest(path, accept, ct) {
		if secFetchSite == "same-origin" && secFetchMode == "no-cors" && secFetchDest == "script" {
			return true
		} else {
			return false
		}
	} else if secFetchSite == "none" && secFetchMode == "navigate" && secFetchDest == "document" {
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

func (h HeaderChecker) DeterminUnRealisticHeaderCount(r *http.Request) bool {
	// count header keys
	count := len(r.Header)
	if h.logger != nil {
		h.logger.Info("header counting",
			zap.Int("Header count is =", count),
		)
	}
	if count < 7 {
		return true
	}
	if count > 25 {
		return true
	}
	return false
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

func CheckCorrectAcceptEncodingCheck(r *http.Request) bool {
	AcceptEncoding := r.Header.Get("Accept-Encoding")
	// Perform a check for the default accept-encoding checks.
	if AcceptEncoding == "gzip, deflate, br, zstd" {
		return true
	}

	return false
}

func (h HeaderChecker) validateAcceptLanguage(AcceptLanguage string) bool {
	// Check for the existence of the Accept-Language. No header is a clear error
	if strings.TrimSpace(AcceptLanguage) == "" {
		if h.logger != nil {
			h.logger.Warn("missing Accept-Language header",
				zap.String("Accept-Language =", AcceptLanguage),
			)
		}
		return true
	}
	for _, char := range AcceptLanguage {
		if char == ' ' {
			h.logger.Warn("Accept-Language header contains a space",
				zap.String("Accept-Language =", AcceptLanguage),
			)
			return true
		}

	}
	return false
}

func cleanHeaderValue(s string) string {
	if unquoted, err := strconv.Unquote(s); err == nil {
		return unquoted
	}
	return s
}
func hasOuterSpaces(s string) bool {
	return s != strings.TrimSpace(s)
}

// ValidateClientHintWindowsPlatformVersion returns true if either:
// - platform is not Windows (no check on version), we need to research how to validate other parts
// - platform is Windows AND version is exactly "19.0.0".
//
// Returns false if platform is Windows but version is missing/incorrect.
func ValidateClientHintWindowsPlatformVersion(platform string, platformVersion string) bool {

	if platform != strings.TrimSpace(platform) || platformVersion != strings.TrimSpace(platformVersion) {
		fmt.Println("DEBUG platform or version has illegal surrounding whitespace")
		return false
	}
	platformlocal := cleanHeaderValue(platform)
	versionlocal := cleanHeaderValue(platformVersion)

	fmt.Println("DEBUG unquoted platform:", fmt.Sprintf("%q", platformlocal))
	fmt.Println("DEBUG unquoted version :", fmt.Sprintf("%q", versionlocal))
	if platformlocal == "" {
		fmt.Println("DEBUG no platform atall return false")
		return false
	}
	if platformlocal != "\"Windows\"" {
		fmt.Println("DEBUG platform is not Windows → return true")
		return true
	}

	if versionlocal == "19.0.0" {
		fmt.Println("DEBUG Windows + version == 19.0.0 → return true")
		return true
	}

	fmt.Println("DEBUG Windows + version != 19.0.0 → return false")
	return false
}

// ServeHTTP inspects the headers and then calls the next handler.
func (h HeaderChecker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.logRequest(r)
	// Simple “is this Firefox at all?” check
	var reFirefox = regexp.MustCompile(`Firefox/\d+\.\d+`)
	var reChrome = regexp.MustCompile(`Chrome/\d+\.\d+`)
	botdetected := false
	if h.validateSecFetchRequests(r) {
		if h.logger != nil {
			h.logger.Warn("There is something strange with the Sec-Fetch headers",
				zap.String("Sec-Fetch-Site", r.Header.Get("Sec-Fetch-Site")),
				zap.String("Sec-Fetch-Mode", r.Header.Get("Sec-Fetch-Mode")),
				zap.String("Sec-Fetch-Dest", r.Header.Get("Sec-Fetch-Dest")),
			)
		}
	}

	if h.validateAcceptLanguage(r.Header.Get("Accept-Language")) {
		if h.logger != nil {
			h.logger.Warn("missing Accept-Language header")
		}
	}
	if IsDevtoolsPath(r) {
		if h.logger != nil {
			h.logger.Warn("Someone is using the devtools block request",
				zap.String("Pat that was excest", r.URL.Path),
			)
		}
	}
	HeaderCheckResult := useragent.ValidateHeaderLength(r.Header)
	if HeaderCheckResult.WithinSpec == false {
		if h.logger != nil {
			h.logger.Warn("The browser requested more or to less headers then normal",
				zap.String("Reason", HeaderCheckResult.Reason),
				zap.String("Browser", string(HeaderCheckResult.Browser)),
				zap.Int("headerlengt", HeaderCheckResult.HeaderLen),
			)
		}
		botdetected = true
	}
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
	//validate the presence of the accept-charset header which is depricated by default
	if r.Header.Get("Accept-Charset") != "" {
		if h.logger != nil {
			h.logger.Warn("Accept-Charset header detected which is depricated and therefor a bot is used",
				zap.String("Accept-header=", r.Header.Get("Accept-Charset")),
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
		if ValidateClientHintWindowsPlatformVersion(r.Header.Get("Sec-CH-UA-Platform"), r.Header.Get("Sec-CH-UA-Platform-Version")) == false {
			if h.logger != nil {
				h.logger.Warn("Windows Platform version client hint is of (could be a patched puppeteer or some other system) ")
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
