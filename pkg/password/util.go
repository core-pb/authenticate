package password

import (
	"crypto/rand"
	"encoding/base64"

	"google.golang.org/protobuf/types/known/structpb"
)

func generateSalt(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func getPassword(data *structpb.Struct) string {
	if data == nil {
		return ""
	}
	val := data.Fields["password"]
	if val == nil {
		return ""
	}

	return val.GetStringValue()
}

func getPasswordBytes(data *structpb.Struct) []byte {
	pwd := getPassword(data)
	if pwd == "" {
		return nil
	}
	b, err := base64.RawStdEncoding.DecodeString(pwd)
	if err != nil {
		return nil
	}
	return b
}

func getSaltBytes(data *structpb.Struct) []byte {
	if data == nil {
		return nil
	}
	salt := data.Fields["salt"]
	if salt == nil {
		return nil
	}
	str := salt.GetStringValue()
	if str == "" {
		return nil
	}
	b, err := base64.RawStdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return b
}
