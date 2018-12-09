package sentry

import (
	"context"
	"errors"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/dgrijalva/jwt-go"
	"github.com/getsentry/raven-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestSentry(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestWhiteboxSentry{})
}

type TestWhiteboxSentry struct {
	suite.Suite
}

func (s *TestWhiteboxSentry) TearDownSuite() {
	sentryClient = nil
}

func failOnNoToken(t *testing.T) context.Context {
	return manager.ContextWithTokenManager(context.Background(), testtoken.TokenManager)
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

func (s *TestWhiteboxSentry) TestExtractUserInfo() {
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
			ctx:     failOnNoToken(s.T()),
			wantErr: true,
		},
		{
			name:    "fail on parsing token",
			ctx:     failOnParsingToken(s.T()),
			wantErr: true,
		},
		{
			name:    "pass on parsing token",
			ctx:     validToken(s.T(), identity),
			wantErr: false,
			want: &raven.User{
				Username: identity.Username,
				ID:       identity.ID.String(),
				Email:    identity.Username,
			},
		},
	}
	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			got, err := extractUserInfo(tt.ctx)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equalf(t, tt.want, got, "extractUserInfo() = %v, want %v", got, tt.want)
		})
	}
}

func (s *TestWhiteboxSentry) TestInitialize() {
	resource.Require(s.T(), resource.UnitTest)
	_, err := InitializeSentryClient(
		"someIncorrectDSN",
		WithRelease("someRelease"),
		WithEnvironment("someEnv"),
	)
	require.Error(s.T(), err)

	haltSentry, err := InitializeSentryClient(
		"https://something:something@domain.com/abc",
		WithRelease("someRelease"),
		WithEnvironment("someEnv"),
	)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), haltSentry)

	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: uuid.NewV4().String(),
	}
	ctx := validToken(s.T(), identity)

	c := Sentry()
	require.NotNil(s.T(), c)
	require.Equal(s.T(), sentryClient, c)

	require.NotPanics(s.T(), func() {
		c.CaptureError(ctx, errors.New("some error"))
	})

	require.NotPanics(s.T(), func() {
		haltSentry()
	})
}
