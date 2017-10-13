package keycloak_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/token/keycloak"

	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type KeycloakExternakTokenTest struct {
	testsuite.RemoteTestSuite
	clean                        func()
	KeycloakExternalTokenService keycloak.KeycloakExternalTokenService
	accessToken                  *string
	keycloakExternalTokenURL     *string
}

func TestRunKeycloakExternakTokenTest(t *testing.T) {
	suite.Run(t, &KeycloakExternakTokenTest{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *KeycloakExternakTokenTest) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	var err error
	s.Config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}

	keycloakExternalTokenService := keycloak.NewKeycloakTokenServiceClient()
	s.KeycloakExternalTokenService = keycloakExternalTokenService
	token, err := s.generateAccessToken()
	assert.Nil(s.T(), err)
	s.accessToken = token

}

func (s *KeycloakExternakTokenTest) generateAccessToken() (*string, error) {

	client := &http.Client{Timeout: 10 * time.Second}
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	tokenEndpoint, err := s.Config.GetKeycloakEndpointToken(r)

	res, err := client.PostForm(tokenEndpoint, url.Values{
		"client_id":     {s.Config.GetKeycloakClientID()},
		"client_secret": {s.Config.GetKeycloakSecret()},
		"username":      {s.Config.GetKeycloakTestUserName()},
		"password":      {s.Config.GetKeycloakTestUserSecret()},
		"grant_type":    {"password"},
	})
	if err != nil {
		return nil, errors.NewInternalError(context.Background(), errs.Wrap(err, "error when obtaining token"))
	}

	t, err := token.ReadTokenSet(context.Background(), res)
	require.Nil(s.T(), err)
	return t.AccessToken, err
}

func (s *KeycloakExternakTokenTest) TestKeycloakTokenGetGithubToken() {
	keycloakExternalTokenURL := fmt.Sprintf("%s/auth/realms/%s/broker/github/token", s.Config.GetKeycloakDevModeURL(), s.Config.GetKeycloakRealm())
	externalToken, err := s.KeycloakExternalTokenService.Get(context.Background(), *s.accessToken, keycloakExternalTokenURL)

	require.Nil(s.T(), err)
	require.NotNil(s.T(), externalToken)

	if strings.Contains(keycloakExternalTokenURL, "github") {
		// github
		require.Len(s.T(), externalToken.AccessToken, 40)
		require.Equal(s.T(), "bearer", externalToken.TokenType)
		require.Equal(s.T(), "admin%3Arepo_hook%2Cgist%2Cread%3Aorg%2Crepo%2Cuser", externalToken.Scope)
	}
}
