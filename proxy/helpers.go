package proxy

import (
	"io/ioutil"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

	"io"
)

// decodeLatin1 - decodes Latin1 string from the reader
func decodeLatin1(reader io.Reader) (string, error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// encodeLatin1 - encodes the string as a byte array using Latin1
func encodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}
