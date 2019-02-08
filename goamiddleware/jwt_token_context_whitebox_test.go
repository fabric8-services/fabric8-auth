package goamiddleware

import (
	"context"
	"errors"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"

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
	assert.NotContains(s.T(), header, "WWW-Authenticate")
	assert.NotContains(s.T(), header, "Access-Control-Expose-Headers")

	// Test with a user token
	rw = httptest.NewRecorder()
	s.Graph.CreateToken()
}

func dummyHandler(ctx context.Context, rw http.ResponseWriter, r *http.Request) error {
	return errors.New("next-handler-error")
}
