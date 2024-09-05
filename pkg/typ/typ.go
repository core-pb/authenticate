package typ

import (
	"net/http"

	"github.com/core-pb/authenticate/authenticate/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	enableType = make(map[authenticate.Type]TypeConfig)
)

func Register(typ authenticate.Type, tc TypeConfig) {
	if _, ok := enableType[typ]; ok {
		panic("type is exist")
	}
	enableType[typ] = tc
}

func Get(typ authenticate.Type) TypeConfig {
	return enableType[typ]
}

func AvailableType() []authenticate.Type {
	arr := make([]authenticate.Type, 0, len(enableType))
	for k := range enableType {
		arr = append(arr, k)
	}
	return arr
}

type TypeConfig interface {
	VerifyConfig(*authenticate.Authenticate) error
	Handler() (string, http.Handler)
	Generate(*authenticate.Authenticate, *structpb.Struct) (*structpb.Struct, error)
}
