package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var XorKey = []byte{0x13, 0x54, 077, 0x1A, 0xA1, 0x3F, 0x04, 0x8B}

func strByXOR(message string, keywords string) string {
	messageLen := len(message)
	keywordsLen := len(keywords)

	result := ""

	for i := 0; i < messageLen; i++ {
		result += string(message[i] ^ keywords[i%keywordsLen])
	}
	return result
}

func Encode(src []byte) string {
	var xsc []byte
	for i := 0; i < len(src); i++ {
		xsc = append(xsc, src[i]^XorKey[2]^XorKey[1])
	}
	bdata := base64.StdEncoding.EncodeToString(xsc)
	fmt.Println(bdata)
	bdata = strings.Replace(bdata, "d", ")", -1)
	bdata = strings.Replace(bdata, "w", "@", -1)
	bdata = strings.Replace(bdata, "k", "*", -1)

	return bdata
}

func main() {
	Encode([]byte("\xfc\x48\x83\xe4......."))
}
