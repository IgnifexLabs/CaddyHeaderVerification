package useragent

import "testing"

func TestValidateReduction(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{name: "iPhone with CriOS (should return true)",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.109 Mobile/15E148 Safari/604.1",
			want: true,
		},
		{
			name: "iPhone with EdgiOS (should return true)",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/143.0.3650.130 Version/26.0 Mobile/15E148 Safari/604.1",
			want: true,
		},
		{
			name: "iPhone with no CriOS or EdgiOS (should return false)",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
			want: false,
		},
		{
			name: "Mac reduced UA (example)",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: true,
		},
		{
			name: "Android reduced UA",
			ua:   "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
			want: true,
		},
		{
			name: "Windows reduced UA",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: true,
		},
		{
			name: "ChromeOS reduced UA",
			ua:   "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: true,
		},
		{
			name: "Linux reduced UA",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: true,
		},
		{
			name: "Upper/lowercase mismatch still matches",
			ua:   "mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/537.36",
			want: false,
		},
		{
			name: "Non‑reduced Mac UA (different version)",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: false,
		},
		{
			name: "Non‑reduced Iphone firefox IOS ",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 Mobile/15E148 Safari/605.1.15",
			want: false,
		},
		{
			name: "iPhone platform UA exact match should return true",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1",
			want: true,
		},
		{
			name: "Non‑reduced Android Linux",
			ua:   "Mozilla/5.0 (Linux; Android 12; V2134) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
			want: false,
		},
		{
			name: "Completely unrelated UA",
			ua:   "curl/8.5.0",
			want: false,
		},
		{
			name: "Empty UA",
			ua:   "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateReduction(tt.ua)
			if got != tt.want {
				t.Errorf("ValidateReduction(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}
