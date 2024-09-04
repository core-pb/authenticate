package structpbutil

import (
	"fmt"
	"reflect"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
)

const fieldTag = "json"

var (
	strType = reflect.TypeOf("")
)

func assignableValueTo(src, dst reflect.Value) error {
	st, dt := src.Type(), dst.Type()
	if !st.AssignableTo(dt) {
		if !st.ConvertibleTo(dt) {
			return fmt.Errorf("cannot assign %s to %s", st, dt)
		}
		src = src.Convert(dt)
	}

	dst.Set(src)
	return nil
}

func ConvertValue(src *structpb.Value, dst reflect.Value) (err error) {
	dst = reflect.Indirect(dst)

	switch t := src.GetKind().(type) {
	case *structpb.Value_BoolValue:
		err = assignableValueTo(reflect.ValueOf(t.BoolValue), dst)
	case *structpb.Value_NullValue:
		err = assignableValueTo(reflect.ValueOf(nil), dst)
	case *structpb.Value_NumberValue:
		err = assignableValueTo(reflect.ValueOf(t.NumberValue), dst)
	case *structpb.Value_StringValue:
		err = assignableValueTo(reflect.ValueOf(t.StringValue), dst)
	case *structpb.Value_ListValue:
		err = ConvertList(t.ListValue, dst)
	case *structpb.Value_StructValue:
		err = ConvertStruct(t.StructValue, dst)
	default:
		err = fmt.Errorf("unsuported value: %T", src.GetKind())
	}

	return
}

func ConvertStruct(src *structpb.Struct, dst reflect.Value) error {
	switch reflect.Indirect(dst).Kind() {
	case reflect.Struct:
		return ConvertStructToStruct(src, dst)
	case reflect.Map:
		return ConvertStructToMap(src, dst)
	default:
		return fmt.Errorf("unsupported convert %T to type %s", src, dst.Type())
	}
}

func ConvertStructToStruct(src *structpb.Struct, dst reflect.Value) error {
	dst = reflect.Indirect(dst)
	if dst.Kind() != reflect.Struct {
		return fmt.Errorf("cannot convert %T to %s", src, dst.Type())
	}

	fields := src.GetFields()

	for i := 0; i < dst.NumField(); i++ {
		var (
			target = dst.Field(i)
			field  = dst.Type().Field(i)
			name   = field.Tag.Get(fieldTag)
		)
		if name == "" {
			name = strings.ToLower(field.Name)
		}

		if v, ok := fields[name]; ok {
			if err := ConvertValue(v, target); err != nil {
				return err
			}
		}
	}

	return nil
}

func ConvertStructToMap(src *structpb.Struct, dst reflect.Value) error {
	dst = reflect.Indirect(dst)
	if dst.Kind() != reflect.Map {
		return fmt.Errorf("cannot convert %T to %s", src, dst.Type())
	}

	var (
		elemType = dst.Type().Elem()
		mapType  = reflect.MapOf(strType, elemType)
		mapVal   = reflect.MakeMap(mapType)
		fields   = src.GetFields()
	)

	for key, value := range fields {
		element := reflect.New(elemType).Elem()
		if err := ConvertValue(value, element); err != nil {
			return err
		}
		mapVal.SetMapIndex(reflect.ValueOf(key), element)
	}

	dst.Set(mapVal)
	return nil
}

func ConvertList(src *structpb.ListValue, dst reflect.Value) error {
	dst = reflect.Indirect(dst)
	if dst.Kind() != reflect.Slice {
		return fmt.Errorf("cannot convert %T to %s", src, dst.Type())
	}

	var (
		values    = src.GetValues()
		elemType  = dst.Type().Elem()
		converted = make([]reflect.Value, len(values))
	)

	for i, value := range values {
		element := reflect.New(elemType).Elem()
		if err := ConvertValue(value, element); err != nil {
			return err
		}
		converted[i] = element
	}
	dst.Set(reflect.Append(dst, converted...))
	return nil
}
