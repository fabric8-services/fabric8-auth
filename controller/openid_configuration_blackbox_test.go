package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestOpenIDConfigurationREST struct {
	suite.Suite
}

func TestRunOpenIDConfigurationREST(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestOpenIDConfigurationREST{})
}

func (s *TestOpenIDConfigurationREST) UnSecuredController() (*goa.Service, *OpenidConfigurationController) {
	svc := goa.New("Status-Service")
	return svc, NewOpenidConfigurationController(svc)
}

func (s *TestOpenIDConfigurationREST) TestShowOpenIDConfiguration() {
	t := s.T()
	svc, ctrl := s.UnSecuredController()

	_, openIDConfiguration := test.ShowOpenidConfigurationOK(t, svc.Context, svc, ctrl)

	issuer := "http://"
	authorizationEndpoint := "http:///api/authorize"
	tokenEndpoint := "http:///api/token"
	logoutEndpoint := "http:///api/logout"
	jwksURI := "http:///api/token/keys"

	expectedOpenIDConfiguration := &app.OpenIDConfiguration{
		Issuer:                            &issuer,
		AuthorizationEndpoint:             &authorizationEndpoint,
		TokenEndpoint:                     &tokenEndpoint,
		EndSessionEndpoint:                &logoutEndpoint,
		ResponseTypesSupported:            []string{"code"},
		JwksURI:                           &jwksURI,
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "offline_access"},
		ClaimsSupported:                   []string{"sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_jwt"},
	}

	require.Equal(t, openIDConfiguration, expectedOpenIDConfiguration)
}
