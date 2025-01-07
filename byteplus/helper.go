package byteplus

import "strings"

func trimStringQuotes(input string) string {
	return strings.TrimPrefix(strings.TrimSuffix(input, "\""), "\"")
}
