package password

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	v1 "github.com/core-pb/authenticate/authenticate/password/v1"
	"github.com/core-pb/authenticate/authenticate/password/v1/passwordconnect"
	auth "github.com/core-pb/authenticate/authenticate/v1"
	"github.com/core-pb/authenticate/authenticate/v1/authenticateconnect"
	"google.golang.org/protobuf/types/known/structpb"
)

type srv struct {
	base authenticateconnect.BaseClient

	passwordconnect.UnimplementedPasswordHandler
}

func (x *srv) Check(ctx context.Context, req *connect.Request[v1.CheckRequest]) (*connect.Response[v1.CheckResponse], error) {
	resp, err := x.base.ListAuthenticate(ctx, connect.NewRequest(&auth.ListAuthenticateRequest{Id: []uint64{req.Msg.Id}}))
	if err != nil {
		return nil, err
	}
	if len(resp.Msg.Data) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("authenticate notfound"))
	}

	var data *AuthenticateData
	if data, err = ParseData(resp.Msg.Data[0].Authenticate); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if !data.Password().CheckPassword(req.Msg.Password, req.Msg.Data) {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	return connect.NewResponse(&v1.CheckResponse{}), nil
}

func (x *srv) Generate(ctx context.Context, req *connect.Request[v1.GenerateRequest]) (*connect.Response[v1.GenerateResponse], error) {
	resp, err := x.base.ListAuthenticate(ctx, connect.NewRequest(&auth.ListAuthenticateRequest{Id: []uint64{req.Msg.Id}}))
	if err != nil {
		return nil, err
	}
	if len(resp.Msg.Data) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("authenticate notfound"))
	}

	var data *AuthenticateData
	if data, err = ParseData(resp.Msg.Data[0].Authenticate); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	var pd *structpb.Struct
	if pd, err = data.Password().GenerateHash(req.Msg.Password); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.GenerateResponse{Data: pd}), nil
}
