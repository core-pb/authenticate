package password

import (
	"google.golang.org/protobuf/types/known/structpb"
)

type Plain struct{}

func (*Plain) Verify() error { return nil }
func (*Plain) GenerateHash(pwd string) (*structpb.Struct, error) {
	return &structpb.Struct{Fields: map[string]*structpb.Value{"password": structpb.NewStringValue(pwd)}}, nil
}
func (*Plain) CheckPassword(pwd string, data *structpb.Struct) bool {
	return getPassword(data) == pwd
}
