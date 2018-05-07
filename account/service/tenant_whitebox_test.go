package service

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/rest"
	authtest "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/goadesign/goa/client"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestTenant(t *testing.T) {
	suite.Run(t, &TestTenantSuite{})
}

type TestTenantSuite struct {
	testsuite.UnitTestSuite
	ts           *tenantService
	doer         *authtest.DummyHttpDoer
	tenantConfig *tenantURLConfig
}

func (s *TestTenantSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.tenantConfig = &tenantURLConfig{ConfigurationData: *s.Config, tenantURL: "https://some.tenant.io"}
	s.ts = NewTenant(s.tenantConfig).(*tenantService)
	doer := authtest.NewDummyHttpDoer()
	s.ts.doer = doer
	s.doer = doer
}

func (s *TestTenantSuite) TestNewInitTenantOK() {
	require.NotNil(s.T(), NewTenant(s.Config))
}

func (s *TestTenantSuite) TestDefaultDoer() {
	ts := NewTenant(s.tenantConfig).(*tenantService)
	assert.Equal(s.T(), ts.config, s.tenantConfig)
	assert.Equal(s.T(), ts.doer, rest.DefaultHttpDoer())
}

func (s *TestTenantSuite) TestInit() {
	ctx, token, reqID := s.newContext()

	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "POST", req.Method)
		assert.Equal(s.T(), "https://some.tenant.io/api/tenant", req.URL.String())
		assert.Equal(s.T(), "Bearer "+token, req.Header.Get("Authorization"))
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))
	}

	// OK
	err := s.ts.Init(ctx)
	require.NoError(s.T(), err)

	// Fail if client returned an error
	s.doer.Client.Response = nil
	s.doer.Client.Error = errors.New("something went wrong")
	err = s.ts.Init(ctx)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "something went wrong", err.Error())

	// Fail if tenant service URL is invalid
	tenant := NewTenant(&tenantURLConfig{ConfigurationData: *s.Config, tenantURL: "::::"})
	ts := tenant.(*tenantService)
	doer := authtest.NewDummyHttpDoer()
	ts.doer = doer
	doer.Client.Error = nil
	body = ioutil.NopCloser(bytes.NewReader([]byte{}))
	doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	err = ts.Init(ctx)
	require.Error(s.T(), err)
}

func (s *TestTenantSuite) TestDelete() {
	ctx, _, reqID := s.newContext()
	ctx = tokencontext.ContextWithTokenManager(ctx, testtoken.TokenManager)

	token := testtoken.TokenManager.AuthServiceAccountToken()
	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusNoContent}
	identityID := uuid.NewV4()
	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "DELETE", req.Method)
		assert.Equal(s.T(), "https://some.tenant.io/api/tenants/"+identityID.String(), req.URL.String())
		assert.Equal(s.T(), "Bearer "+token, req.Header.Get("Authorization"))
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))
	}

	// OK
	err := s.ts.Delete(ctx, identityID)
	require.NoError(s.T(), err)

	// Fail if returned anything but No Contented
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusNotFound}
	err = s.ts.Delete(ctx, identityID)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "unable to delete tenant", err.Error())

	// Fail if client returned an error
	s.doer.Client.Response = nil
	s.doer.Client.Error = errors.New("something went wrong")
	err = s.ts.Delete(ctx, identityID)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "something went wrong", err.Error())
}

func (s *TestTenantSuite) newContext() (context.Context, string, string) {
	ctx, ctxToken, err := token.EmbedTokenInContext(uuid.NewV4().String(), uuid.NewV4().String())
	require.NoError(s.T(), err)

	reqID := uuid.NewV4().String()
	ctx = client.SetContextRequestID(ctx, reqID)

	return ctx, ctxToken, reqID
}

type tenantURLConfig struct {
	configuration.ConfigurationData
	tenantURL string
}

func (c *tenantURLConfig) GetTenantServiceURL() string {
	return c.tenantURL
}
