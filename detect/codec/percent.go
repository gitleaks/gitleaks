package codec

// decodePercent decodes percent encoded strings
func decodePercent(encodedValue string) string {
	encLen := len(encodedValue)
	decodedValue := make([]byte, encLen)
	decIndex := 0
	encIndex := 0

	for encIndex < encLen {
		if encodedValue[encIndex] == '%' && encIndex+2 < encLen {
			n1 := hexMap[encodedValue[encIndex+1]]
			n2 := hexMap[encodedValue[encIndex+2]]
			// Make sure they're hex characters
			if n1|n2 != '\xff' {
				b := n1<<4 | n2
				if !printableASCII[b] {
					return ""
				}

				decodedValue[decIndex] = b
				encIndex += 3
				decIndex += 1
				continue
			}
		}

		decodedValue[decIndex] = encodedValue[encIndex]
		encIndex += 1
		decIndex += 1
	}

	return string(decodedValue[:decIndex])
}
