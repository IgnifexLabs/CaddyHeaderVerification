package headerchecker

import (
	"net/http"
	"testing"
)

func TestCheckCorrectAcceptEncodingCheck(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{
			name:   "Empty Accept-Encoding header → false",
			header: http.Header{},
			want:   false,
		},
		{
			name: "Whitespace Accept-Encoding header → false",
			header: http.Header{
				"Accept-Encoding": []string{"   "},
			},
			want: false,
		},
		{
			name: "Default value `gzip, deflate, br, zstd` → false",
			header: http.Header{
				"Accept-Encoding": []string{"gzip, deflate, br, zstd"},
			},
			want: true,
		},
		{
			name: "Different encoding value → true",
			header: http.Header{
				"Accept-Encoding": []string{"gzip, deflate"},
			},
			want: false,
		},
		{
			name: "Same encodings but different order → true",
			header: http.Header{
				"Accept-Encoding": []string{"br, gzip, deflate, zstd"},
			},
			want: false,
		},
		{
			name: "Same encodings with extra space → true",
			header: http.Header{
				"Accept-Encoding": []string{"gzip, deflate, br, zstd "},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: tt.header}
			got := CheckCorrectAcceptEncodingCheck(req)
			if got != tt.want {
				t.Errorf("CheckCorrectAcceptEncodingCheck() = %v, want %v, header=%v",
					got, tt.want, tt.header.Get("Accept-Encoding"))
			}
		})
	}
}
