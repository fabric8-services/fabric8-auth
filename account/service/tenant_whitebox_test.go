package service

import (
	"context"
	"testing"

	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/dgrijalva/jwt-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestTenant(t *testing.T) {
	suite.Run(t, &TestTenantSuite{})
}

type TestTenantSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestTenantSuite) TestNewInitTenantOK() {
	require.NotNil(s.T(), NewTenant(s.Config))
}

func (s *TestTenantSuite) TestCreateClientOK() {
	claims := jwt.MapClaims{}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	ctx := goajwt.WithJWT(context.Background(), token)

	c, err := createClient(ctx, &dummyConfig{})
	require.Nil(s.T(), err)
	require.NotNil(s.T(), c)
}

type dummyConfig struct {
}

func (c *dummyConfig) GetTenantServiceURL() string {
	return "https://tenant.local"
}
