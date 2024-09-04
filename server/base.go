package main

import (
	"context"

	"github.com/core-pb/authenticate/authenticate/v1"
	"github.com/core-pb/dt/time/v1"
	"github.com/redis/rueidis"
	"github.com/uptrace/bun"
)

var (
	db    *bun.DB
	cache rueidis.Client
)

type Authenticate struct {
	bun.BaseModel `bun:"table:authenticate"`
	*authenticate.Authenticate
}

type AuthenticateTag struct {
	bun.BaseModel `bun:"table:authenticate_tag"`
	*authenticate.AuthenticateTag
}

type AuthenticateDetail struct {
	bun.BaseModel `bun:"table:user"`
	*authenticate.Authenticate

	AuthenticateTag []*AuthenticateTag `bun:"rel:has-many,join:id=authenticate_id"`
}

func (x *Authenticate) BeforeAppendModel(_ context.Context, query bun.Query) error {
	if x.Authenticate == nil {
		x.Authenticate = &authenticate.Authenticate{}
	}

	t := time.Now()
	switch query.(type) {
	case *bun.InsertQuery:
		if x.CreatedAt == nil {
			x.CreatedAt = t
		}
		if x.UpdatedAt == nil {
			x.UpdatedAt = t
		}
	case *bun.UpdateQuery:
		x.UpdatedAt = t
	}
	return nil
}

func (*Authenticate) AfterCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	if _, err := query.DB().NewCreateIndex().IfNotExists().Model((*Authenticate)(nil)).
		Index("idx_authenticate").Column("type", "scope", "disable", "data").
		Exec(ctx); err != nil {
		return err
	}
	return nil
}
