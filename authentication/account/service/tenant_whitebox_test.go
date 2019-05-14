package service

import (
	"bytes"
	"errors"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/rest"
	authtest "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestTenantService(t *testing.T) {
	suite.Run(t, &TestTenantServiceSuite{})
}

type TestTenantServiceSuite struct {
	testsuite.UnitTestSuite
	doer         *authtest.DummyHttpDoer
	ts           *tenantServiceImpl
	tenantConfig *tenantURLConfig
}

func (s *TestTenantServiceSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.tenantConfig = &tenantURLConfig{ConfigurationData: s.Config, tenantURL: "https://some.tenant.io"}
	s.ts = NewTenantService(s.tenantConfig).(*tenantServiceImpl)
	doer := authtest.NewDummyHttpDoer()
	s.ts.doer = doer
	s.doer = doer
}

func (s *TestTenantServiceSuite) TestNewInitTenantOK() {
	require.NotNil(s.T(), NewTenantService(s.Config))
}

func (s *TestTenantServiceSuite) TestDefaultDoer() {
	ts := NewTenantService(s.tenantConfig).(*tenantServiceImpl)
	assert.Equal(s.T(), ts.config, s.tenantConfig)
	assert.Equal(s.T(), ts.doer, rest.DefaultHttpDoer())
}

func (s *TestTenantServiceSuite) TestInit() {
	ctx, token, reqID := testtoken.ContextWithTokenAndRequestID(s.T())

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
	tenant := NewTenantService(&tenantURLConfig{ConfigurationData: s.Config, tenantURL: "::::"})
	ts := tenant.(*tenantServiceImpl)
	doer := authtest.NewDummyHttpDoer()
	ts.doer = doer
	doer.Client.Error = nil
	body = ioutil.NopCloser(bytes.NewReader([]byte{}))
	doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	err = ts.Init(ctx)
	require.Error(s.T(), err)
}

func (s *TestTenantServiceSuite) TestView() {
	ctx, token, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	ctx = manager.ContextWithTokenManager(ctx, testtoken.TokenManager)

	json, err := ioutil.ReadFile("../../../test/data/tenant_single.json")
	require.NoError(s.T(), err)

	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader(json))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		require.Equal(s.T(), "GET", req.Method)
		require.Equal(s.T(), "https://some.tenant.io/api/tenant", req.URL.String())
		require.Equal(s.T(), "Bearer "+token, req.Header.Get("Authorization"))
		require.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))
	}

	tenant, err := s.ts.View(ctx)
	require.NoError(s.T(), err)

	require.Equal(s.T(), "00000000-0000-0000-0000-000000000123", tenant.Data.ID.String())
}

func (s *TestTenantServiceSuite) TestDelete() {
	ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	ctx = manager.ContextWithTokenManager(ctx, testtoken.TokenManager)

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

	// OK if returned Not Found
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusNotFound}
	err = s.ts.Delete(ctx, identityID)
	require.NoError(s.T(), err)

	// Fail if returned another error
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError}
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

type tenantURLConfig struct {
	*configuration.ConfigurationData
	tenantURL string
}

func (c *tenantURLConfig) GetTenantServiceURL() string {
	return c.tenantURL
}
