package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

type LoginServiceConfiguration interface {
	login.Configuration
	GetKeycloakEndpointAuth(*goa.RequestData) (string, error)
	GetKeycloakURL() string
	GetKeycloakRealm() string
	GetPublicOauthClientID() string
	GetServiceAccounts() map[string]configuration.ServiceAccount
}

type loginServiceImpl struct {
	base.BaseService
	config LoginServiceConfiguration
}

func NewLoginService(context servicecontext.ServiceContext, conf LoginServiceConfiguration) service.LoginService {
	return &loginServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      conf,
	}
}

// Login is responsible for redirecting the client to the authentication service in order to authenticate
func (s *loginServiceImpl) Login(ctx context.Context, config oauth.OauthConfig) (*string, error) {
	// Redirect to the oauth provider
	generatedState := uuid.NewV4().String()
	redirectURL, err := s.Services().AuthenticationProviderService().AuthCodeURL(ctx, ctx.Redirect, ctx.APIClient, &generatedState, nil, ctx.RequestData, config)
	if err != nil {
		return nil, err
	}
	return redirectURL, nil
	ctx.ResponseData.Header().Set("Location", *redirectURL)
	return ctx.TemporaryRedirect()
}

// Callback is invoked after the client has visited the authentication service and state and code values are returned
func (s *loginServiceImpl) Callback(ctx context.Context, state string, code string) error {

	// After redirect from oauth provider
	log.Debug(ctx, map[string]interface{}{
		"code":  code,
		"state": state,
	}, "Redirected from oauth provider")

	referrerURL, _, err := keycloak.reclaimReferrerAndResponseMode(ctx, state, code)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	keycloakToken, err := keycloak.Exchange(ctx, code, config)

	if err != nil {
		jsonapi.JSONErrorResponse(ctx, err)
		ctx.ResponseData.Header().Set("Location", referrerURL.String()+"?error="+err.Error())
		return ctx.TemporaryRedirect()
	}

	redirectTo, _, err := keycloak.CreateOrUpdateIdentityAndUser(ctx, referrerURL, keycloakToken, ctx.RequestData, serviceConfig)
	if err != nil {
		jsonapi.JSONErrorResponse(ctx, err)
	}

	if redirectTo != nil {
		ctx.ResponseData.Header().Set("Location", *redirectTo)
		return ctx.TemporaryRedirect()
	}

	ctx.ResponseData.Header().Set("Location", referrerURL.String()+"?error="+err.Error())
	return ctx.TemporaryRedirect()
}
