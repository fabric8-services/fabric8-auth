package goamiddleware

import (
	"context"
	"errors"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testJWTokenContextSuite struct {
	gormtestsupport.DBTestSuite
}

func TestJWTTokenContextSuite(t *testing.T) {
	suite.Run(t, &testJWTokenContextSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *testJWTokenContextSuite) TestHandler() {
	schema := &goa.JWTSecurity{}
	errUnauthorized := goa.NewErrorClass("token_validation_failed", 401)

	rw := httptest.NewRecorder()
	rq := &http.Request{Header: make(map[string][]string)}
	h := handler(s.Application, testtoken.TokenManager, schema, dummyHandler, errUnauthorized)

	err := h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "whoops, security scheme with location (in) \"\" not supported", err.Error())

	// OK if no Authorization header
	schema.In = "header"
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "next-handler-error", err.Error())

	// OK if not bearer
	schema.Name = "Authorization"
	rq.Header.Set("Authorization", "something")
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "next-handler-error", err.Error())

	// Get 401 if token is invalid
	rq.Header.Set("Authorization", "Bearer token")
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "401 token_validation_failed: token is invalid", err.Error())
	assert.Equal(s.T(), "LOGIN url=http://localhost/api/login, description=\"re-login is required\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")

	// OK if token is valid
	rw = httptest.NewRecorder()
	t, err := testtoken.TokenManager.GenerateServiceAccountToken(uuid.NewV4().String(), "sa-name")
	require.NoError(s.T(), err)
	rq.Header.Set("Authorization", "Bearer "+t)
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "next-handler-error", err.Error())
	header := textproto.MIMEHeader(rw.Header())
	require.Empty(s.T(), header.Get("WWW-Authenticate"))
	require.Empty(s.T(), header.Get("Access-Control-Expose-Headers"))

	// Test with a user token
	rw = httptest.NewRecorder()
	tkn := s.Graph.CreateToken()
	rq.Header.Set("Authorization", "Bearer "+tkn.TokenString())
	now := time.Now()
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "next-handler-error", err.Error())
	header = textproto.MIMEHeader(rw.Header())
	require.Empty(s.T(), header.Get("WWW-Authenticate"))
	require.Empty(s.T(), header.Get("Access-Control-Expose-Headers"))
	// Confirm that the identity's last active timestamp has been updated
	identity := s.Graph.LoadIdentity(tkn.Token().IdentityID)
	require.True(s.T(), now.Before(*identity.Identity().LastActive))

	// Test with an invalid user token
	rw = httptest.NewRecorder()
	tkn = s.Graph.CreateToken()
	// Flag the token as revoked
	tkn.Token().Status = token.TOKEN_STATUS_REVOKED
	err = s.Application.TokenRepository().Save(s.Ctx, tkn.Token())
	require.NoError(s.T(), err)
	rq.Header.Set("Authorization", "Bearer "+tkn.TokenString())
	err = h(context.Background(), rw, rq)
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "401 token_validation_failed: token is invalid", err.Error())
	header = textproto.MIMEHeader(rw.Header())
	require.Equal(s.T(), "LOGIN url=http://localhost/api/login, description=\"re-login is required\"", header.Get("WWW-Authenticate"))
	assert.Contains(s.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

func dummyHandler(ctx context.Context, rw http.ResponseWriter, r *http.Request) error {
	return errors.New("next-handler-error")
}
