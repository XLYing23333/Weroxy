package quicklist

import "unicode"

// Width uses terminal columns; tabs themselves are added by the renderer.
func terminalWidth(value string) int {
	width := 0
	for _, r := range value {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == 0x200d {
			continue
		}
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hangul, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || (r >= 0x3000 && r <= 0x303f) || (r >= 0xff01 && r <= 0xff60) || (r >= 0x1f300 && r <= 0x1faff) {
			width += 2
		} else {
			width++
		}
	}
	return width
}
