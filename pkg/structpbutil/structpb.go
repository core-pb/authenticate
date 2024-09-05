package structpbutil

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/structpb"
)

func Unmarshal(data *structpb.Struct, v any) error {
	val, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(val, v)
}

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
