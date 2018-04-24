package sentry

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	"github.com/getsentry/raven-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

func failOnNoToken(t *testing.T) context.Context {
	return tokencontext.ContextWithTokenManager(context.Background(), testtoken.TokenManager)
}

func failOnParsingToken(t *testing.T) context.Context {
	ctx := failOnNoToken(t)
	// Here we add a token which is incomplete
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	ctx = goajwt.WithJWT(ctx, token)
	return ctx
}

func validToken(t *testing.T, identity account.Identity) context.Context {
	ctx, err := testtoken.EmbedIdentityInContext(identity)
	require.Nil(t, err)
	return ctx
}
func TestExtractUserInfo(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: uuid.NewV4().String(),
	}

	tests := []struct {
		name    string
		ctx     context.Context
		want    *raven.User
		wantErr bool
	}{
		{
			name:    "Given some random context",
			ctx:     context.Background(),
			wantErr: true,
		},
		{
			name:    "fail on no token",
			ctx:     failOnNoToken(t),
			wantErr: true,
		},
		{
			name:    "fail on parsing token",
			ctx:     failOnParsingToken(t),
			wantErr: true,
		},
		{
			name:    "pass on parsing token",
			ctx:     validToken(t, identity),
			wantErr: false,
			want: &raven.User{
				Username: identity.Username,
				ID:       identity.ID.String(),
				Email:    identity.Username,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractUserInfo(tt.ctx)
			if tt.wantErr {
				require.Error(t, err)
				// if above assertion passes we don't need to continue
				// to check if objects match
				return
			}
			require.NoError(t, err)
			require.Equalf(t, tt.want, got, "extractUserInfo() = %v, want %v", got, tt.want)
		})
	}
}
