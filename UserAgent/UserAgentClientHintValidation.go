package useragent

import "strings"

var allowedBrands = []string{
	"Google Chrome",
	"Microsoft Edge",
	"Brave",
}

// IsBotFromSecChUa returns true if the Sec-Ch-Ua header
// does NOT contain any of the allowed brands.
func IsBotFromSecChUa(secChUa string) bool {

	// Examples of bad headers header:
	//  77 Sec-Ch-Ua":["\"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"128\""] Only chromium
	// 39 Sec-Ch-Ua":[""] en empty sec-ch-ua?
	// 27 Sec-Ch-Ua":["\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"HeadlessChrome\";v=\"138\""] HeadlessChrome
	lower := strings.ToLower(secChUa)
	if secChUa == "" {
		// No header at all: treat as bot (up to you)
		return true
	}
	for _, brand := range allowedBrands {
		if strings.Contains(lower, strings.ToLower(brand)) {
			// This looks like a mainstream browser
			return false
		}
	}

	// No allowed brand found => treat as bot
	return true
}
