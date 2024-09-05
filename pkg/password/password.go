package password

import (
	"errors"
	"net/http"

	pc "github.com/core-pb/authenticate/authenticate/password/v1/passwordconnect"
	"github.com/core-pb/authenticate/authenticate/v1"
	"github.com/core-pb/authenticate/authenticate/v1/authenticateconnect"
	"github.com/core-pb/authenticate/pkg/structpbutil"
	"github.com/core-pb/authenticate/pkg/typ"
	"google.golang.org/protobuf/types/known/structpb"
)

func Enable(client authenticateconnect.BaseClient) typ.TypeConfig {
	s := &srv{base: client}
	typ.Register(authenticate.Type_TYPE_PASSWORD, s)
	return s
}

func (x *srv) Handler() (string, http.Handler) { return pc.NewPasswordHandler(x) }
func (x *srv) VerifyConfig(val *authenticate.Authenticate) error {
	data, err := ParseData(val)
	if err != nil {
		return err
	}

	return data.Password().Verify()
}

func (x *srv) Generate(val *authenticate.Authenticate, req *structpb.Struct) (*structpb.Struct, error) {
	data, err := ParseData(val)
	if err != nil {
		return nil, err
	}

	pwd := getPassword(req)
	if pwd == "" {
		return nil, errors.New("invalid password")
	}

	return data.Password().GenerateHash(pwd)
}

func ParseData(val *authenticate.Authenticate) (*AuthenticateData, error) {
	if val == nil {
		return nil, errors.New("invalid config")
	}

	var data AuthenticateData
	if err := structpbutil.Unmarshal(val.Data, &data); err != nil {
		return nil, err
	}
	if data.Password() == nil {
		return nil, errors.New("invalid password")
	}
	return &data, nil
}

type Password interface {
	GenerateHash(pwd string) (*structpb.Struct, error)
	CheckPassword(pwd string, data *structpb.Struct) bool

	Verify() error
}

type AuthenticateData struct {
	Type     string    `json:"type"`
	Plain    *Plain    `json:"plain"`
	Argon2id *Argon2id `json:"argon2id"`
	Bcrypt   *Bcrypt   `json:"bcrypt"`
	Scrypt   *Scrypt   `json:"scrypt"`
}

func (a *AuthenticateData) Password() Password {
	switch a.Type {
	case "plain":
		return a.Plain
	case "argon2id":
		return a.Argon2id
	case "bcrypt":
		return a.Bcrypt
	case "scrypt":
		return a.Scrypt
	default:
		return nil
	}
}
