package strictjson

import "unicode/utf8"

// ValidUnicode rejects invalid UTF-8 and lone UTF-16 surrogate escapes before
// encoding/json can replace them. Escaped backslashes are skipped as pairs;
// general JSON syntax remains the decoder's responsibility.
func ValidUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for index := 0; index < len(data); index++ {
		if data[index] != '\\' {
			continue
		}
		index++
		if index >= len(data) || data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return false
		}
		first, ok := hex4(data[index+1 : index+5])
		if !ok {
			return false
		}
		if first >= 0xDC00 && first <= 0xDFFF {
			return false
		}
		index += 4
		if first >= 0xD800 && first <= 0xDBFF {
			if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			second, valid := hex4(data[index+3 : index+7])
			if !valid || second < 0xDC00 || second > 0xDFFF {
				return false
			}
			index += 6
		}
	}
	return true
}

func hex4(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, char := range value {
		result <<= 4
		switch {
		case char >= '0' && char <= '9':
			result |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			result |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			result |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
