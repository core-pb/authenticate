package password

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/structpb"
)

type Bcrypt struct {
	Cost int `json:"cost"`
}

func (x *Bcrypt) GenerateHash(pwd string) (*structpb.Struct, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(pwd), x.Cost)
	if err != nil {
		return nil, err
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"password": structpb.NewStringValue(base64.RawStdEncoding.EncodeToString(hashed)),
	}}, nil
}

func (x *Bcrypt) CheckPassword(pwd string, data *structpb.Struct) bool {
	hashed := getPasswordBytes(data)
	if len(hashed) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hashed, []byte(pwd)) == nil
}

func (x *Bcrypt) Verify() error {
	if x == nil {
		return errors.New("invalid argument")
	}
	if x.Cost < bcrypt.MinCost || x.Cost > bcrypt.MaxCost {
		return errors.New("invalid argument: cost, 4 <= cost <= 31")
	}
	return nil
}
