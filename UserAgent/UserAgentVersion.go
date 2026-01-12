package useragent

import "regexp"

var (
	oldChromeRe     = regexp.MustCompile(`Chrome/([0-9]{1,2}|1[0-3][0-9])\.[0-9]`)
	oldFirefoxRe    = regexp.MustCompile(`Firefox/([0-9]{1,2}|1[0-3][0-9])\.[0-9]`)
	oldEdgeRe       = regexp.MustCompile(`Edg/([0-9]{1,2}|1[0-3][0-9])\.[0-9]`)
	oldFirefoxIOSRe = regexp.MustCompile(`FxiOS/([0-9]{1,2}|1[0-3][0-9])\.[0-9]`)
	oldChromeIOSRe  = regexp.MustCompile(`CriOS/([0-9]{1,2}|1[0-3][0-9])\.[0-9]`)
)

func IsOldBrowser(ua string) bool {
	return IsOldChrome(ua) ||
		IsOldFirefox(ua) ||
		IsOldFirefoxIOS(ua) ||
		IsOldChromeIOS(ua) ||
		IsOldEdge(ua)
}
func IsOldEdge(ua string) bool {
	return oldEdgeRe.MatchString(ua)
}

func IsOldChrome(ua string) bool {
	return oldChromeRe.MatchString(ua)
}

func IsOldFirefox(ua string) bool {
	return oldFirefoxRe.MatchString(ua)
}

func IsOldFirefoxIOS(ua string) bool {
	return oldFirefoxIOSRe.MatchString(ua)
}

func IsOldChromeIOS(ua string) bool {
	return oldChromeIOSRe.MatchString(ua)
}
