package service

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"net/url"
	"regexp"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"

	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

type LogoutServiceConfiguration interface {
	GetValidRedirectURLs() string
	GetOAuthProviderEndpointLogout() string
}

type logoutServiceImpl struct {
	base.BaseService
	config LogoutServiceConfiguration
}

func NewLogoutService(context servicecontext.ServiceContext, config LogoutServiceConfiguration) service.LogoutService {
	return &logoutServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

func (s *logoutServiceImpl) Logout(ctx context.Context, redirectURL string) (string, error) {

	if redirectURL == "" {
		log.Error(ctx, map[string]interface{}{
			"redirect_url":       redirectURL,
			"valid_redirect_url": s.config.GetValidRedirectURLs(),
		}, "Redirect URL is not valid")
		return "", errors.NewBadParameterErrorFromString("redirect", redirectURL, "not valid redirect URL")
	}
	matched, err := regexp.MatchString(s.config.GetValidRedirectURLs(), redirectURL)
	log.Debug(ctx, map[string]interface{}{
		"redirect_url":        redirectURL,
		"valid_redirect_urls": s.config.GetValidRedirectURLs(),
		"matched":             matched,
		"error":               err,
	}, "matched redirect URL and whitelist regex")
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url":        redirectURL,
			"valid_redirect_urls": s.config.GetValidRedirectURLs(),
			"err":                 err,
		}, "Can't match redirect URL and whitelist regex")
		return "", errors.NewInternalError(err)
	}
	if !matched {
		log.Error(ctx, map[string]interface{}{
			"redirect_url":       redirectURL,
			"valid_redirect_url": s.config.GetValidRedirectURLs(),
		}, "Redirect URL is not valid")
		return "", errors.NewBadParameterErrorFromString("redirect", redirectURL, "not valid redirect URL")
	}
	logoutURL, err := url.Parse(s.config.GetOAuthProviderEndpointLogout())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"logout_endpoint": s.config.GetOAuthProviderEndpointLogout(),
			"err":             err,
		}, "Failed to logout. Unable to parse logout url.")
		return "", errors.NewInternalError(err)
	}

	parameters := logoutURL.Query()
	parameters.Add("redirect_uri", redirectURL)
	logoutURL.RawQuery = parameters.Encode()

	// If an access token was passed in the context, then set the status to "logged out" for all tokens with the same identity
	tkn := goajwt.ContextJWT(ctx)
	if tkn != nil {

		claims := tkn.Claims.(jwt.MapClaims)

		sub := claims["sub"]
		if sub == nil {
			return "", errors.NewUnauthorizedError("missing 'sub' claim in the refresh token")
		}

		err = s.ExecuteInTransaction(func() error {
			identityID, err := uuid.FromString(fmt.Sprintf("%s", sub))
			if err != nil {
				return errors.NewUnauthorizedError(err.Error())
			}

			err = s.Services().TokenService().SetStatusForAllIdentityTokens(ctx, identityID, token.TOKEN_STATUS_LOGGED_OUT)
			if err != nil {
				return errors.NewInternalError(err)
			}

			// Update the identity's last active timestamp on logout
			err = s.Repositories().Identities().TouchLastActive(ctx, identityID)
			if err != nil {
				return errors.NewInternalError(err)
			}

			return nil
		})

		if err != nil {
			return "", err
		}
	}

	return logoutURL.String(), nil
}
