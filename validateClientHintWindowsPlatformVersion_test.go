package headerchecker

import (
	"testing"
)

func TestValidateClientHintWindowsPlatformVersion(t *testing.T) {
	tests := []struct {
		name            string
		platform        string
		platformVersion string
		want            bool
	}{
		{
			name:            "Windows with correct version 19.0.0",
			platform:        `"\"Windows\""`,
			platformVersion: `"19.0.0"`,
			want:            true,
		},
		{
			name:            "Windows with incorrect version 18.0.0",
			platform:        `"\"Windows\""`,
			platformVersion: `"18.0.0"`,
			want:            false,
		},
		{
			name:            "Windows with missing version header",
			platform:        `"\"Windows\""`,
			platformVersion: "",
			want:            false,
		},
		{
			name:            "Windows with empty version value",
			platform:        `"\"Windows\""`,
			platformVersion: "",
			want:            false,
		},
		{
			name:            "Windows without quotes but correct version",
			platform:        "Windows",
			platformVersion: "19.0.0",
			want:            false,
		},
		{
			name:            "Non-Windows platform (macOS) with any version → allowed",
			platform:        `"macOS"`,
			platformVersion: `"14.0.0"`,
			want:            true,
		},
		{
			name:            "Non-Windows platform (Android) without version → allowed",
			platform:        `"Android"`,
			platformVersion: "",
			want:            true,
		},
		{
			name:            "No platform at all → treated as non-Windows",
			platform:        "",
			platformVersion: "",
			want:            false,
		},
		{
			name:            "Windows with extra spaces and quotes, correct version",
			platform:        `  "Windows"  `,
			platformVersion: `  "19.0.0"  `,
			want:            false,
		},
		{
			name:            "Windows with extra spaces, wrong version",
			platform:        `  "Windows"  `,
			platformVersion: `  "20.0.0"  `,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateClientHintWindowsPlatformVersion(
				tt.platform,
				tt.platformVersion,
			)

			if got != tt.want {
				t.Errorf(
					"ValidateClientHintWindowsPlatformVersion(%q, %q) = %v, want %v",
					tt.platform,
					tt.platformVersion,
					got,
					tt.want,
				)
			}
		})
	}
}
