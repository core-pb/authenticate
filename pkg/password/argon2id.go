package password

import (
	"bytes"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/types/known/structpb"
)

type Argon2id struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
	SaltLen uint32 `json:"salt_len"`
}

func (x *Argon2id) CheckPassword(pwd string, data *structpb.Struct) bool {
	var (
		hashed = getPasswordBytes(data)
		salt   = getSaltBytes(data)
	)

	if len(hashed) == 0 || len(salt) == 0 {
		return false
	}

	return bytes.Equal(hashed, argon2.IDKey([]byte(pwd), salt, x.Time, x.Memory, x.Threads, x.KeyLen))
}

func (x *Argon2id) GenerateHash(pwd string) (*structpb.Struct, error) {
	salt, err := generateSalt(int(x.SaltLen))
	if err != nil {
		return nil, err
	}
	hashed := argon2.IDKey([]byte(pwd), salt, x.Time, x.Memory, x.Threads, x.KeyLen)

	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"password": structpb.NewStringValue(base64.RawStdEncoding.EncodeToString(hashed)),
		"salt":     structpb.NewStringValue(base64.RawStdEncoding.EncodeToString(salt)),
	}}, nil
}

func (x *Argon2id) Verify() error {
	if x == nil {
		return errors.New("invalid argument")
	}

	if x.Time < 1 || x.Time > 16 {
		return errors.New("invalid argument: time, 1 <= time <= 16")
	}
	if x.Memory < 1024 || x.Memory > 1024*1024 {
		return errors.New("invalid argument: memory, 1M <= memory <= 1G")
	}

	const maxCost = (64 * 1024) * 16 // memory: 64M, time: 16
	if x.Memory*x.Time > maxCost {
		return errors.New("invalid argument: cost to high")
	}

	if x.Threads == 0 || x.Threads > 4 { // k8s node doesn’t have many cores
		return errors.New("invalid argument: too many threads")
	}
	if x.KeyLen < 16 || x.KeyLen > 256 {
		return errors.New("invalid argument: keyLen, 16 <= keyLen <= 256")
	}
	if x.SaltLen < 16 || x.SaltLen > 64 {
		return errors.New("invalid argument: saltLen, 16 <= saltLen <= 64")
	}

	return nil
}
