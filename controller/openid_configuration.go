package controller

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
)

// OpenidConfigurationController implements the openid_configuration resource.
type OpenidConfigurationController struct {
	*goa.Controller
	Configuration LoginConfiguration
}

// NewOpenidConfigurationController creates a openid_configuration controller.
func NewOpenidConfigurationController(service *goa.Service) *OpenidConfigurationController {
	return &OpenidConfigurationController{Controller: service.NewController("OpenidConfigurationController")}
}

// Show runs the show action.
func (c *OpenidConfigurationController) Show(ctx *app.ShowOpenidConfigurationContext) error {
	//keycloakOpenIDConfigurationEndpoint := c.Configuration.GetKeycloakURL() + "/auth/realms/" + c.Configuration.GetKeycloakRealm() + "/.well-known/openid-configuration"
	// TODO: Instead of using the hardcoded URL, get it from function(s)^
	keycloakOpenIDConfigurationEndpoint := "https://sso.prod-preview.openshift.io/auth/realms/fabric8-test/.well-known/openid-configuration"
	response, err := http.Get(keycloakOpenIDConfigurationEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "request to achieve openid-configuration of keycloak failed")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err.Error())
	}
	keycloakOpenIDConfiguration := &app.OpenIDConfiguration{}
	err = json.Unmarshal(body, keycloakOpenIDConfiguration)
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "unable to unmashal to json")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	issuer := rest.AbsoluteURL(ctx.RequestData, "")
	authorizationEndpoint := rest.AbsoluteURL(ctx.RequestData, client.AuthorizeAuthorizePath())
	tokenEndpoint := rest.AbsoluteURL(ctx.RequestData, client.ExchangeTokenPath())

	authOpenIDConfiguration := &app.OpenIDConfiguration{
		Issuer:                &issuer,
		AuthorizationEndpoint: &authorizationEndpoint,
		TokenEndpoint:         &tokenEndpoint,
	}

	return ctx.OK(authOpenIDConfiguration)
}
