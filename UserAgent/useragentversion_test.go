package useragent

import "testing"

func TestIsOldChrome(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{"Chrome 50", "Mozilla/5.0 Chrome/50.0.2661.102 Safari/537.36", true},
		{"Chrome 130", "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36", true}, // <=139
		{"Chrome 139", "Mozilla/5.0 Chrome/139.0.0.0 Safari/537.36", true},
		{"Chrome 140", "Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36", false},
		{"Non Chrome", "Mozilla/5.0 Firefox/125.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOldChrome(tt.ua)
			if got != tt.want {
				t.Errorf("IsOldChrome(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestIsOldFirefox(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{"Firefox 50", "Mozilla/5.0 Firefox/50.0", true},
		{"Firefox 130", "Mozilla/5.0 Firefox/130.0", true}, // <=139
		{"Firefox 139", "Mozilla/5.0 Firefox/139.0", true},
		{"Firefox 140", "Mozilla/5.0 Firefox/140.0", false},
		{"Non Firefox", "Mozilla/5.0 Chrome/120.0.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOldFirefox(tt.ua)
			if got != tt.want {
				t.Errorf("IsOldFirefox(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestIsOldFirefoxIOS(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{"FxiOS 50", "Mozilla/5.0 FxiOS/50.0 Mobile/15E148 Safari/604.1", true},
		{"FxiOS 130", "Mozilla/5.0 FxiOS/130.0 Mobile/15E148 Safari/604.1", true},
		{"FxiOS 139", "Mozilla/5.0 FxiOS/139.0 Mobile/15E148 Safari/604.1", true},
		{"FxiOS 140", "Mozilla/5.0 FxiOS/140.0 Mobile/15E148 Safari/604.1", false},
		{"Non FxiOS", "Mozilla/5.0 Firefox/120.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOldFirefoxIOS(tt.ua)
			if got != tt.want {
				t.Errorf("IsOldFirefoxIOS(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestIsOldChromeIOS(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{"CriOS 50", "Mozilla/5.0 CriOS/50.0.2661.102 Mobile/15E148 Safari/604.1", true},
		{"CriOS 130", "Mozilla/5.0 CriOS/130.0.0.0 Mobile/15E148 Safari/604.1", true},
		{"CriOS 139", "Mozilla/5.0 CriOS/139.0.0.0 Mobile/15E148 Safari/604.1", true},
		{"CriOS 140", "Mozilla/5.0 CriOS/140.0.0.0 Mobile/15E148 Safari/604.1", false},
		{"Non CriOS", "Mozilla/5.0 Chrome/120.0.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOldChromeIOS(tt.ua)
			if got != tt.want {
				t.Errorf("IsOldChromeIOS(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestIsOldBrowser(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{"Old Chrome", "Mozilla/5.0 Chrome/80.0.3987.132 Safari/537.36", true},
		{"Old Firefox", "Mozilla/5.0 Firefox/90.0", true},
		{"Old FxiOS", "Mozilla/5.0 FxiOS/100.0 Mobile Safari/604.1", true},
		{"Old CriOS", "Mozilla/5.0 CriOS/100.0.0.0 Mobile Safari/604.1", true},
		{"New Chrome", "Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36", false},
		{"Unrelated UA", "curl/8.5.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOldBrowser(tt.ua)
			if got != tt.want {
				t.Errorf("IsOldBrowser(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}
