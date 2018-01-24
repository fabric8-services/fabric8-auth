package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/client"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/rest"

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

	u := &url.URL{
		Path: fmt.Sprintf(client.ShowOpenidConfigurationPath()),
	}
	prms := url.Values{}
	req, err := http.NewRequest("GET", u.String(), nil)

	ctx := context.Background()
	rw := httptest.NewRecorder()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "OpenIDConfigurationTest"), rw, req, prms)
	openIDConfigurationCtx, err := app.NewShowOpenidConfigurationContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)

	issuer := rest.AbsoluteURL(openIDConfigurationCtx.RequestData, "")
	authorizationEndpoint := rest.AbsoluteURL(openIDConfigurationCtx.RequestData, client.AuthorizeAuthorizePath())
	tokenEndpoint := rest.AbsoluteURL(openIDConfigurationCtx.RequestData, client.ExchangeTokenPath())
	logoutEndpoint := rest.AbsoluteURL(openIDConfigurationCtx.RequestData, client.LogoutLogoutPath())
	jwksURI := rest.AbsoluteURL(openIDConfigurationCtx.RequestData, client.KeysTokenPath())

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
		ClaimsSupported:                   []string{"email", "full_name", "email", "image_url", "bio", "url", "company", "cluster", "email_verified", "email_private", "feature_level"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_jwt"},
	}

	require.Equal(t, openIDConfiguration, expectedOpenIDConfiguration)
}
