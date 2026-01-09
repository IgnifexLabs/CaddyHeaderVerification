package useragent

import "strings"

type UserAgentReduction string

const (
	PlatformAndroid  UserAgentReduction = "Android 10; K"
	PlatformMac      UserAgentReduction = "Macintosh; Intel Mac OS X 10_15_7"
	PlatformWindows  UserAgentReduction = "Windows NT 10.0; Win64; x64"
	PlatformChromeOS UserAgentReduction = "X11; CrOS x86_64 14541.0.0"
	PlatformLinux    UserAgentReduction = "X11; Linux x86_64"
)

var allReducedPatterns = []UserAgentReduction{
	PlatformAndroid,
	PlatformMac,
	PlatformWindows,
	PlatformChromeOS,
	PlatformLinux,
}

func ValidateReduction(ua string) bool {
	uaLower := strings.ToLower(ua)

	for _, pattern := range allReducedPatterns {
		if strings.Contains(uaLower, strings.ToLower(string(pattern))) {
			return true
		}
	}
	return false
}
