package headerchecker

import (
	"net/http/httptest"
	"testing"
)

func TestValidateSecFetchRequests(t *testing.T) {
	h := HeaderChecker{}

	tests := []struct {
		name      string
		headers   map[string]string
		urlPath   string
		wantValid bool
	}{
		{
			name:      "empty headers => false",
			headers:   map[string]string{},
			urlPath:   "/some/path",
			wantValid: false,
		},
		{
			name: "valid image request with correct Sec-Fetch headers => true",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "image",
				"Accept":         "image/webp,image/apng,image/*,*/*;q=0.8",
				"Content-Type":   "image/png",
			},
			urlPath:   "/images/photo.png",
			wantValid: true,
		},
		{
			name: "image request with incorrect Sec-Fetch headers => false",
			headers: map[string]string{
				"Sec-Fetch-Site": "cross-site",
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "image",
				"Accept":         "image/webp,image/apng,image/*,*/*;q=0.8",
				"Content-Type":   "image/png",
			},
			urlPath:   "/images/photo.png",
			wantValid: false,
		},
		{
			name: "valid navigate request => true",
			headers: map[string]string{
				"Sec-Fetch-Site": "none",
				"Sec-Fetch-Mode": "navigate",
				"Sec-Fetch-Dest": "document",
			},
			urlPath:   "/home",
			wantValid: true,
		},
		{
			name: "invalid navigate request (missing header) => false",
			headers: map[string]string{
				"Sec-Fetch-Site": "none",
				// missing Sec-Fetch-Mode
				"Sec-Fetch-Dest": "document",
			},
			urlPath:   "/home",
			wantValid: false,
		},
		{
			name: "non-image and non-navigate request same server => true",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "script",
			},
			urlPath:   "/scripts/app.js",
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.urlPath, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := h.validateSecFetchRequests(req)
			if got != tt.wantValid {
				t.Errorf("validateSecFetchRequests() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}
