package password

import (
	"bytes"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/scrypt"
	"google.golang.org/protobuf/types/known/structpb"
)

type Scrypt struct {
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	KeyLen  int    `json:"key_len"`
	SaltLen uint32 `json:"salt_len"`
}

func (x *Scrypt) GenerateHash(pwd string) (*structpb.Struct, error) {
	salt, err := generateSalt(int(x.SaltLen))
	if err != nil {
		return nil, err
	}
	var hashed []byte
	if hashed, err = scrypt.Key([]byte(pwd), salt, x.N, x.R, x.P, x.KeyLen); err != nil {
		return nil, err
	}

	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"password": structpb.NewStringValue(base64.RawStdEncoding.EncodeToString(hashed)),
		"salt":     structpb.NewStringValue(base64.RawStdEncoding.EncodeToString(salt)),
	}}, nil
}

func (x *Scrypt) CheckPassword(pwd string, data *structpb.Struct) bool {
	var (
		hashed = getPasswordBytes(data)
		salt   = getSaltBytes(data)
	)
	if len(hashed) == 0 || len(salt) == 0 {
		return false
	}
	if val, err := scrypt.Key([]byte(pwd), salt, x.N, x.R, x.P, x.KeyLen); err == nil {
		return bytes.Equal(hashed, val)
	}
	return false
}

func (x *Scrypt) Verify() error {
	if x == nil {
		return errors.New("invalid argument")
	}

	if x.N <= 1 || x.N&(x.N-1) != 0 {
		return errors.New("invalid argument: N must be > 1 and a power of 2")
	}

	if x.N < 1<<15 || x.N > 1<<20 {
		return errors.New("invalid argument: N, 1<<15 <= N <= 1<<20")
	}
	if x.R < 8 || x.R > 128 {
		return errors.New("invalid argument: R, 8 <= R <= 128")
	}
	if x.P < 1 || x.R > 32 {
		return errors.New("invalid argument: P, 1 <= P <= 32")
	}

	if x.KeyLen < 16 || x.KeyLen > 256 {
		return errors.New("invalid argument: keyLen, 16 <= keyLen <= 256")
	}
	if x.SaltLen < 16 || x.SaltLen > 64 {
		return errors.New("invalid argument: saltLen, 16 <= saltLen <= 64")
	}

	const maxInt = int(^uint(0) >> 1)
	if uint64(x.R)*uint64(x.P) >= 1<<30 || x.R > maxInt/128/x.P || x.R > maxInt/256 || x.N > maxInt/128/x.R {
		return errors.New("invalid argument: too large, satisfy r * p < 2^30")
	}

	return nil
}
