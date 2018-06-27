package auth_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/auth"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	configuration *config.ConfigurationData
	scopes        = []string{"read:test", "admin:test"}
)

func init() {
	var err error
	configuration, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func TestAuth(t *testing.T) {
	if configuration.IsKeycloakTestsDisabled() {
		t.Skip("Skipping Keycloak AuthZ tests")
	}
	resource.Require(t, resource.Remote)
	suite.Run(t, new(TestAuthSuite))
}

type TestAuthSuite struct {
	suite.Suite
}

func (s *TestAuthSuite) SetupSuite() {
}

func (s *TestAuthSuite) TestGetProtectedAPITokenOK() {
	token := getProtectedAPITokenOK(s.T())
	require.NotEqual(s.T(), "", token)
}

func (s *TestAuthSuite) TestReadTokenOK() {
	b := closer{bytes.NewBufferString("{\"access_token\":\"accToken\", \"expires_in\":3000000, \"refresh_expires_in\":2, \"refresh_token\":\"refToken\"}")}
	response := http.Response{Body: b}
	t, err := token.ReadTokenSet(context.Background(), &response)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "accToken", *t.AccessToken)
	assert.Equal(s.T(), int64(3000000), *t.ExpiresIn)
	assert.Equal(s.T(), int64(2), *t.RefreshExpiresIn)
	assert.Equal(s.T(), "refToken", *t.RefreshToken)
}

func getProtectedAPITokenOK(t *testing.T) string {
	r := &goa.RequestData{
		Request: &http.Request{Host: "demo.api.openshift.io"},
	}

	endpoint, err := configuration.GetKeycloakEndpointToken(r)
	require.Nil(t, err)
	token, err := auth.GetProtectedAPIToken(context.Background(), endpoint, configuration.GetKeycloakClientID(), configuration.GetKeycloakSecret())
	require.Nil(t, err)
	return token
}

type closer struct {
	io.Reader
}

func (closer) Close() error {
	return nil
}
