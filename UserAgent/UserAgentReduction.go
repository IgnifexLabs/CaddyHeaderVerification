package useragent

import "strings"

type UserAgentReduction string

const (
	PlatformAndroid  UserAgentReduction = "Android 10; K"
	PlatformMac      UserAgentReduction = "Macintosh; Intel Mac OS X 10_15_7"
	PlatformWindows  UserAgentReduction = "Windows NT 10.0; Win64; x64"
	PlatformChromeOS UserAgentReduction = "X11; CrOS x86_64 14541.0.0"
	PlatformLinux    UserAgentReduction = "X11; Linux x86_64"
	PlatformIphone   UserAgentReduction = "iPhone; CPU iPhone OS 18_7 like Mac OS X"
	PlatformIpad     UserAgentReduction = "iPad; CPU OS 18_7 like Mac OS X"
)

var allReducedPatterns = []UserAgentReduction{
	PlatformAndroid,
	PlatformMac,
	PlatformWindows,
	PlatformChromeOS,
	PlatformLinux,
	PlatformIphone,
	PlatformIpad,
}

func ValidateReduction(ua string) bool {
	if strings.Contains(ua, "iPhone; CPU iPhone OS") && (strings.Contains(ua, "CriOS") || strings.Contains(ua, "EdgiOS")) {
		return true
	}

	for _, pattern := range allReducedPatterns {
		if strings.Contains(ua, string(pattern)) {
			return true
		}
	}
	return false
}
