package structpbutil

import (
	"encoding/json"
	"reflect"

	"google.golang.org/protobuf/types/known/structpb"
)

func Unmarshal(data *structpb.Struct, v any) error {
	if data == nil || data.Fields == nil {
		return nil
	}
	return ConvertStruct(data, reflect.ValueOf(v))
}

// Marshal struct to structpb.Struct
//
// TODO: use reflect
func Marshal(v any) (*structpb.Struct, error) {
	val, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	m := make(map[string]any)
	if err = json.Unmarshal(val, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}
