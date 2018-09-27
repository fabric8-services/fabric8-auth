package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/login"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"net/url"
)

type LoginServiceConfiguration interface {
	//GetKeycloakEndpointAuth(*goa.RequestData) (string, error)
	//GetKeycloakURL() string
	//GetKeycloakRealm() string
	//GetPublicOauthClientID() string
	//GetServiceAccounts() map[string]configuration.ServiceAccount
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

// Callback is invoked after the client has visited the authentication provider and state and code values are returned.
// These two parameters will be exchanged with the authentication provider for an access token, which will be returned
// to the client.
func (s *loginServiceImpl) Callback(ctx context.Context, state string, code string) error {

	// After redirect from oauth provider
	log.Debug(ctx, map[string]interface{}{
		"code":  code,
		"state": state,
	}, "Redirected from oauth provider")

	referrerURL, _, err := s.reclaimReferrerAndResponseMode(ctx, state, code)
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

// reclaimReferrer reclaims referrerURL and verifies the state
func (s *loginServiceImpl) reclaimReferrerAndResponseMode(ctx context.Context, state string, code string) (*url.URL, *string, error) {
	knownReferrer, responseMode, err := s.loadReferrerAndResponseMode(ctx, state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "unknown state")
		return nil, nil, errors.NewUnauthorizedError("unknown state: " + err.Error())
	}
	referrerURL, err := url.Parse(knownReferrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code":           code,
			"state":          state,
			"known_referrer": knownReferrer,
			"err":            err,
		}, "failed to parse referrer")
		return nil, nil, errors.NewInternalError(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"code":           code,
		"state":          state,
		"known_referrer": knownReferrer,
		"response_mode":  responseMode,
	}, "referrer found")

	return referrerURL, responseMode, nil
}

// loadReferrerAndResponseMode loads referrer and responseMode from DB
func (s *loginServiceImpl) loadReferrerAndResponseMode(ctx context.Context, state string) (string, *string, error) {
	var referrer string
	var responseMode *string

	err := s.ExecuteInTransaction(func() error {
		ref, err := s.Repositories().OauthStates().Load(ctx, state)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to load oauth state reference")
			return err
		}
		referrer = ref.Referrer
		responseMode = ref.ResponseMode
		err = s.Repositories().OauthStates().Delete(ctx, ref.ID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to delete oauth state reference")
			return err
		}

		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return referrer, responseMode, nil
}
