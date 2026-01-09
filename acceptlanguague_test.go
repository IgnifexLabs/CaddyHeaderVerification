package headerchecker

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestValidateAcceptLanguage_Empty(t *testing.T) {
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.AddCaller()))
	h := HeaderChecker{logger: logger}

	tests := []struct {
		name           string
		acceptLanguage string
		want           bool
	}{
		{
			name:           "empty string",
			acceptLanguage: "",
			want:           true, // should log and return true
		},
		{
			name:           "only spaces",
			acceptLanguage: "   ",
			want:           true, // should log and return true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.validateAcceptLanguage(tt.acceptLanguage)
			if got != tt.want {
				t.Fatalf("validateAcceptLanguage(%q) = %v, want %v",
					tt.acceptLanguage, got, tt.want)
			}
		})
	}
}

func TestValidateAcceptLanguage_NonEmpty(t *testing.T) {
	logger := zaptest.NewLogger(t)
	h := HeaderChecker{logger: logger}

	tests := []struct {
		name           string
		acceptLanguage string
	}{
		{
			name:           "simple language",
			acceptLanguage: "en-US",
		},
		{
			name:           "multiple languages",
			acceptLanguage: "nl,nl-NL;q=0.9,en-US;q=0.8,en;q=0.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.validateAcceptLanguage(tt.acceptLanguage)
			if got {
				t.Fatalf("validateAcceptLanguage(%q) = true, want false", tt.acceptLanguage)
			}
		})
	}
}
