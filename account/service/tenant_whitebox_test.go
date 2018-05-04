package service

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/rest"
	authtest "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"

	"bytes"
	"context"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/configuration"
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
	s.ts = s.newTenant()
	doer := authtest.NewDummyHttpDoer()
	s.ts.doer = doer
	s.doer = doer
}

func (s *TestTenantSuite) TestNewInitTenantOK() {
	require.NotNil(s.T(), NewTenant(s.Config))
}

func (s *TestTenantSuite) TestDefaultDoer() {
	ts := s.newTenant()
	assert.Equal(s.T(), ts.config, s.tenantConfig)
	assert.Equal(s.T(), ts.doer, rest.DefaultHttpDoer())
}

func (s *TestTenantSuite) TestInitOK() {
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

	err := s.ts.Init(ctx)
	require.NoError(s.T(), err)
}

func (s *TestTenantSuite) newTenant() *tenantService {
	tenant := NewTenant(s.tenantConfig)
	require.NotNil(s.T(), tenant)
	require.IsType(s.T(), &tenantService{}, tenant)

	return tenant.(*tenantService)
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
