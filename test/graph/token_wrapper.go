package graph

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"time"
)

// tokenWrapper represents a Token domain object
type tokenWrapper struct {
	baseWrapper
	token       *tokenRepo.Token
	tokenString string
}

func loadTokenWrapper(g *TestGraph, tokenID uuid.UUID) tokenWrapper {
	w := tokenWrapper{baseWrapper: baseWrapper{g}}

	var native tokenRepo.Token
	err := w.graph.db.Table("token").Where("token_id = ?", tokenID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.token = &native

	return w
}

func newTokenWrapper(g *TestGraph, params []interface{}) interface{} {
	w := tokenWrapper{baseWrapper: baseWrapper{g}}

	w.token = &tokenRepo.Token{}

	var identity *repository.Identity
	var expiryTime *time.Time
	tokenType := token.TOKEN_TYPE_ACCESS

	for i := range params {
		switch t := params[i].(type) {
		case *string:
			if token.IsValidTokenType(*t) {
				tokenType = *t
			}
		case string:
			if token.IsValidTokenType(t) {
				tokenType = t
			}
		case *time.Time:
			expiryTime = t
		case time.Time:
			expiryTime = &t
		case *userWrapper:
			identity = t.Identity()
		case userWrapper:
			identity = t.Identity()
		case *identityWrapper:
			identity = t.Identity()
		case identityWrapper:
			identity = t.Identity()
		}
	}

	if identity == nil {
		identity = w.graph.CreateUser().Identity()
	}

	w.token.IdentityID = identity.ID

	if expiryTime != nil {
		w.token.ExpiryTime = *expiryTime
	}

	w.token.TokenType = tokenType

	oauthToken, err := testtoken.TokenManager.GenerateUserTokenForIdentity(g.ctx, *identity, false)
	require.NoError(g.t, err)

	if tokenType == token.TOKEN_TYPE_ACCESS || tokenType == token.TOKEN_TYPE_RPT {
		w.tokenString = oauthToken.AccessToken
		w.token.TokenID = w.extractTokenID(g.t, g.ctx, oauthToken.AccessToken)

	} else if tokenType == token.TOKEN_TYPE_REFRESH {
		w.tokenString = oauthToken.RefreshToken
		w.token.TokenID = w.extractTokenID(g.t, g.ctx, oauthToken.RefreshToken)
	}

	err = g.app.TokenRepository().Create(g.ctx, w.token)
	require.NoError(g.t, err)

	return &w
}

func (w *tokenWrapper) extractTokenID(t require.TestingT, ctx context.Context, tokenString string) uuid.UUID {
	claims, err := testtoken.TokenManager.ParseToken(ctx, tokenString)
	require.NoError(t, err)
	tokenID, err := uuid.FromString(claims.Id)
	require.NoError(t, err)
	return tokenID
}

func (w *tokenWrapper) Token() *tokenRepo.Token {
	return w.token
}

func (w *tokenWrapper) TokenString() string {
	return w.tokenString
}

func (w *tokenWrapper) TokenID() uuid.UUID {
	return w.token.TokenID
}

func (w *tokenWrapper) AddPrivilege(params ...interface{}) *tokenWrapper {
	var privilegeCacheID uuid.UUID

	for i := range params {
		switch t := params[i].(type) {
		case *privilegeCacheWrapper:
			privilegeCacheID = t.PrivilegeCache().PrivilegeCacheID
		}

		w.graph.db.Exec("INSERT INTO token_privilege (token_id, privilege_cache_id) VALUES (?, ?)", w.token.TokenID, privilegeCacheID)
	}
	return w
}

func (w *tokenWrapper) RemovePrivilege(params ...interface{}) *tokenWrapper {
	var privilegeCacheID uuid.UUID

	for i := range params {
		switch t := params[i].(type) {
		case *privilegeCacheWrapper:
			privilegeCacheID = t.PrivilegeCache().PrivilegeCacheID
		}

		w.graph.db.Exec("DELETE FROM token_privilege WHERE token_id = ? AND privilege_cache_id = ?", w.token.TokenID, privilegeCacheID)
	}
	return w
}
