// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: authenticate/v1/authenticate_tag.proto

package authenticate

import (
	v1 "github.com/core-pb/dt/time/v1"
	_ "github.com/srikrsna/protoc-gen-gotag/tagger"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AuthenticateTag struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthenticateId uint64           `protobuf:"fixed64,1,opt,name=authenticate_id,json=authenticateId,proto3" json:"authenticate_id,omitempty" bun:",pk,autoincrement"`
	TagId          uint64           `protobuf:"fixed64,2,opt,name=tag_id,json=tagId,proto3" json:"tag_id,omitempty"`
	SourceId       uint64           `protobuf:"fixed64,3,opt,name=source_id,json=sourceId,proto3" json:"source_id,omitempty"`
	Data           *structpb.Struct `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty" bun:"type:jsonb"`
	CreatedAt      *v1.Time         `protobuf:"bytes,14,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty" bun:"type:timestamptz"`
	UpdatedAt      *v1.Time         `protobuf:"bytes,15,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty" bun:"type:timestamptz"`
}

func (x *AuthenticateTag) Reset() {
	*x = AuthenticateTag{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authenticate_v1_authenticate_tag_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateTag) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateTag) ProtoMessage() {}

func (x *AuthenticateTag) ProtoReflect() protoreflect.Message {
	mi := &file_authenticate_v1_authenticate_tag_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateTag.ProtoReflect.Descriptor instead.
func (*AuthenticateTag) Descriptor() ([]byte, []int) {
	return file_authenticate_v1_authenticate_tag_proto_rawDescGZIP(), []int{0}
}

func (x *AuthenticateTag) GetAuthenticateId() uint64 {
	if x != nil {
		return x.AuthenticateId
	}
	return 0
}

func (x *AuthenticateTag) GetTagId() uint64 {
	if x != nil {
		return x.TagId
	}
	return 0
}

func (x *AuthenticateTag) GetSourceId() uint64 {
	if x != nil {
		return x.SourceId
	}
	return 0
}

func (x *AuthenticateTag) GetData() *structpb.Struct {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *AuthenticateTag) GetCreatedAt() *v1.Time {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *AuthenticateTag) GetUpdatedAt() *v1.Time {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

var File_authenticate_v1_authenticate_tag_proto protoreflect.FileDescriptor

var file_authenticate_v1_authenticate_tag_proto_rawDesc = []byte{
	0x0a, 0x26, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x61, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13, 0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f,
	0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x74, 0x69,
	0x6d, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xe6, 0x02, 0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x54, 0x61, 0x67, 0x12, 0x45, 0x0a, 0x0f, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x06, 0x42, 0x1c, 0x9a,
	0x84, 0x9e, 0x03, 0x17, 0x62, 0x75, 0x6e, 0x3a, 0x22, 0x2c, 0x70, 0x6b, 0x2c, 0x61, 0x75, 0x74,
	0x6f, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x52, 0x0e, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x49, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x74,
	0x61, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x06, 0x52, 0x05, 0x74, 0x61, 0x67,
	0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x06, 0x52, 0x08, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x12,
	0x42, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x15, 0x9a, 0x84, 0x9e, 0x03, 0x10, 0x62, 0x75, 0x6e,
	0x3a, 0x22, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x6a, 0x73, 0x6f, 0x6e, 0x62, 0x22, 0x52, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x49, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61,
	0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x42, 0x1b, 0x9a, 0x84, 0x9e, 0x03, 0x16, 0x62, 0x75, 0x6e,
	0x3a, 0x22, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x74, 0x7a, 0x22, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x49,
	0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x42, 0x1b, 0x9a, 0x84, 0x9e, 0x03, 0x16, 0x62, 0x75, 0x6e, 0x3a, 0x22, 0x74, 0x79, 0x70,
	0x65, 0x3a, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x74, 0x7a, 0x22, 0x52, 0x09,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2d, 0x70, 0x62, 0x2f,
	0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x2f, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_authenticate_v1_authenticate_tag_proto_rawDescOnce sync.Once
	file_authenticate_v1_authenticate_tag_proto_rawDescData = file_authenticate_v1_authenticate_tag_proto_rawDesc
)

func file_authenticate_v1_authenticate_tag_proto_rawDescGZIP() []byte {
	file_authenticate_v1_authenticate_tag_proto_rawDescOnce.Do(func() {
		file_authenticate_v1_authenticate_tag_proto_rawDescData = protoimpl.X.CompressGZIP(file_authenticate_v1_authenticate_tag_proto_rawDescData)
	})
	return file_authenticate_v1_authenticate_tag_proto_rawDescData
}

var file_authenticate_v1_authenticate_tag_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_authenticate_v1_authenticate_tag_proto_goTypes = []any{
	(*AuthenticateTag)(nil), // 0: authenticate.v1.AuthenticateTag
	(*structpb.Struct)(nil), // 1: google.protobuf.Struct
	(*v1.Time)(nil),         // 2: time.v1.Time
}
var file_authenticate_v1_authenticate_tag_proto_depIdxs = []int32{
	1, // 0: authenticate.v1.AuthenticateTag.data:type_name -> google.protobuf.Struct
	2, // 1: authenticate.v1.AuthenticateTag.created_at:type_name -> time.v1.Time
	2, // 2: authenticate.v1.AuthenticateTag.updated_at:type_name -> time.v1.Time
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_authenticate_v1_authenticate_tag_proto_init() }
func file_authenticate_v1_authenticate_tag_proto_init() {
	if File_authenticate_v1_authenticate_tag_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_authenticate_v1_authenticate_tag_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*AuthenticateTag); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_authenticate_v1_authenticate_tag_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_authenticate_v1_authenticate_tag_proto_goTypes,
		DependencyIndexes: file_authenticate_v1_authenticate_tag_proto_depIdxs,
		MessageInfos:      file_authenticate_v1_authenticate_tag_proto_msgTypes,
	}.Build()
	File_authenticate_v1_authenticate_tag_proto = out.File
	file_authenticate_v1_authenticate_tag_proto_rawDesc = nil
	file_authenticate_v1_authenticate_tag_proto_goTypes = nil
	file_authenticate_v1_authenticate_tag_proto_depIdxs = nil
}
