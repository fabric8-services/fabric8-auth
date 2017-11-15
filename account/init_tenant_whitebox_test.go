package account

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/dgrijalva/jwt-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestInitTenant(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestInitTenantSuite{})
}

type TestInitTenantSuite struct {
	suite.Suite
	config *configuration.ConfigurationData
}

func (s *TestInitTenantSuite) SetupSuite() {
	var err error
	s.config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("failed to setup the configuration: %s", err.Error()))
	}
}

func (s *TestInitTenantSuite) TearDownSuite() {
}

func (s *TestInitTenantSuite) TestNewInitTenantOK() {
	require.NotNil(s.T(), NewInitTenant(s.config))
}

func (s *TestInitTenantSuite) TestCreateClientOK() {
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
