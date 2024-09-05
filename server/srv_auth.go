package main

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	v1 "github.com/core-pb/authenticate/authenticate/v1"
	"github.com/core-pb/authenticate/authenticate/v1/authenticateconnect"
	"github.com/core-pb/authenticate/pkg/typ"
	"github.com/core-pb/tag/client"
	"github.com/core-pb/tag/tag/v1"
	"github.com/uptrace/bun"
)

type base struct {
	authenticateconnect.UnimplementedBaseHandler
}

func (base) ListAuthenticate(ctx context.Context, req *connect.Request[v1.ListAuthenticateRequest]) (*connect.Response[v1.ListAuthenticateResponse], error) {
	sq := db.NewSelect().Model(&Authenticate{})
	sq = InOrEqPure(sq, `"authenticate".id`, req.Msg.Id)
	sq = InOrEqPure(sq, `"authenticate".type`, req.Msg.Type)
	sq = QueryFormStruct(sq, `"authenticate".data`, req.Msg.Data)
	sq = QueryFormStruct(sq, `"authenticate".info`, req.Msg.Info)
	if req.Msg.Disable != nil {
		sq = sq.Where(`"authenticate".disable = ?`, *req.Msg.Disable)
	}

	sq = Pagination(sq, req.Msg.Pagination)
	sq = Sorts(sq, req.Msg.Sort)

	var (
		arr        []*AuthenticateDetail
		ids        []uint64
		count, err = sq.ScanAndCount(ctx, &ids)
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	if err = db.NewSelect().
		Model(&arr).
		Relation("AuthenticateTag").
		Where(`"id" IN (?)`, bun.In(ids)).
		Scan(ctx); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.ListAuthenticateResponse{
		Data: Array2Array(arr, func(a1 *AuthenticateDetail) *v1.AuthenticateDetail {
			return &v1.AuthenticateDetail{
				Authenticate:    a1.Authenticate,
				AuthenticateTag: Array2Array(a1.AuthenticateTag, func(a1 *AuthenticateTag) *v1.AuthenticateTag { return a1.AuthenticateTag }),
			}
		}), Count: int64(count),
	}), nil
}

func (base) AddAuthenticate(ctx context.Context, req *connect.Request[v1.AddAuthenticateRequest]) (*connect.Response[v1.AddAuthenticateResponse], error) {
	val := &Authenticate{Authenticate: &v1.Authenticate{
		Type:    req.Msg.Type,
		Disable: req.Msg.Disable,
		Data:    req.Msg.Data,
		Info:    req.Msg.Info,
	}}

	tc := typ.Get(val.Type)
	if tc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not support type"))
	}
	if err := tc.VerifyConfig(val.Authenticate); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if _, err := db.NewInsert().Model(val).Returning("*").Exec(ctx); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&v1.AddAuthenticateResponse{Data: val.Authenticate}), nil
}

func (base) SetAuthenticate(ctx context.Context, req *connect.Request[v1.SetAuthenticateRequest]) (*connect.Response[v1.SetAuthenticateResponse], error) {
	if err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ts := tx.NewUpdate().Model(&Authenticate{}).Where("id IN =", req.Msg.Id).Returning("*")

		if req.Msg.Disable != nil {
			ts.Set("disable = ?", req.Msg.Disable)
		}
		if req.Msg.Type != nil {
			ts.Set(`"type" = ?`, req.Msg.Type)
		}
		if req.Msg.Data != nil {
			ts.Set(`"data" = ?`, req.Msg.Data)
		}
		if req.Msg.Info != nil {
			ts.Set(`"info" = ?`, req.Msg.Info)
		}

		_, err := ts.Exec(ctx)
		return err
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.SetAuthenticateResponse{}), nil
}

func (base) DeleteAuthenticate(ctx context.Context, req *connect.Request[v1.DeleteAuthenticateRequest]) (*connect.Response[v1.DeleteAuthenticateResponse], error) {
	if err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewDelete().Model(&Authenticate{}).Where("id IN (?)", req.Msg.Id).Exec(ctx)
		return err
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.DeleteAuthenticateResponse{}), nil
}

func (base) SetTag(ctx context.Context, req *connect.Request[v1.SetTagRequest]) (*connect.Response[v1.SetTagResponse], error) {
	resp, err := client.Internal().BindRelation(ctx, connect.NewRequest(&tag.BindRelationRequest{
		ModuleId:   module.Id,
		ExternalId: req.Msg.AuthenticateId,
		TagId:      req.Msg.TagId,
		Data:       req.Msg.Data,
	}))
	if err != nil {
		return nil, err
	}

	if err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if len(resp.Msg.CleanTagId) != 0 {
			if _, err = tx.NewSelect().Model(&AuthenticateTag{}).Where(`authenticate_id = ? AND tag_id IN (?)`, req.Msg.AuthenticateId, bun.In(resp.Msg.CleanTagId)).Exec(ctx); err != nil {
				return err
			}
		}

		arr := make([]*AuthenticateTag, 0, 1+len(resp.Msg.InheritTagId))
		arr = append(arr, &AuthenticateTag{AuthenticateTag: &v1.AuthenticateTag{
			AuthenticateId: req.Msg.AuthenticateId,
			TagId:          req.Msg.TagId,
			Data:           req.Msg.Data,
		}})

		for _, v := range resp.Msg.InheritTagId {
			arr = append(arr, &AuthenticateTag{AuthenticateTag: &v1.AuthenticateTag{
				AuthenticateId: req.Msg.AuthenticateId,
				TagId:          v,
				SourceId:       req.Msg.TagId,
			}})
		}

		if _, err = tx.NewInsert().On("CONFLICT (authenticate_id,tag_id) DO UPDATE").
			Set("source_id = EXCLUDED.source_id, data = EXCLUDED.data").Model(&arr).Exec(ctx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.SetTagResponse{}), nil
}

func (base) DeleteTag(ctx context.Context, req *connect.Request[v1.DeleteTagRequest]) (*connect.Response[v1.DeleteTagResponse], error) {
	resp, err := client.Internal().UnbindRelation(ctx, connect.NewRequest(&tag.UnbindRelationRequest{
		ModuleId:   module.Id,
		ExternalId: req.Msg.AuthenticateId,
		TagId:      req.Msg.TagId,
	}))
	if err != nil {
		return nil, err
	}

	if err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if len(resp.Msg.CleanTagId) != 0 {
			if _, err = tx.NewSelect().Model(&AuthenticateTag{}).Where(`authenticate_id = ? AND tag_id IN (?)`,
				req.Msg.AuthenticateId, bun.In(resp.Msg.CleanTagId)).Exec(ctx); err != nil {
				return err
			}
		}

		arr := make([]uint64, 0, 1+len(resp.Msg.CleanTagId))
		arr = append(arr, req.Msg.TagId)
		arr = append(arr, resp.Msg.CleanTagId...)

		if _, err = tx.NewDelete().Model(&AuthenticateTag{}).Where(`authenticate_id = ? AND tag_id IN (?)`,
			req.Msg.AuthenticateId, bun.In(resp.Msg.CleanTagId)).Exec(ctx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&v1.DeleteTagResponse{}), nil

}

func (base) AvailableType(_ context.Context, _ *connect.Request[v1.AvailableTypeRequest]) (*connect.Response[v1.AvailableTypeResponse], error) {
	return connect.NewResponse(&v1.AvailableTypeResponse{Type: typ.AvailableType()}), nil
}

func (base) Generate(ctx context.Context, req *connect.Request[v1.GenerateRequest]) (*connect.Response[v1.GenerateResponse], error) {
	auth := new(v1.Authenticate)
	if err := db.NewSelect().Model(&Authenticate{}).Where("id = ?", req.Msg.Id).Scan(ctx, auth); err != nil {
		return nil, err
	}

	tc := typ.Get(auth.Type)
	if tc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not support type"))
	}

	data, err := tc.Generate(auth, req.Msg.Data)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&v1.GenerateResponse{Data: data}), nil
}
