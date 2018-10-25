package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"net/url"
	"regexp"
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

	matched, err := regexp.MatchString(s.config.GetValidRedirectURLs(), redirectURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url":        redirectURL,
			"valid_redirect_urls": s.config.GetValidRedirectURLs(),
			"err": err,
		}, "Can't match redirect URL and whitelist regex")
		return "", errors.NewInternalError(ctx, err)
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
		return "", errors.NewInternalError(ctx, err)
	}

	parameters := logoutURL.Query()
	parameters.Add("redirect_uri", redirectURL)
	logoutURL.RawQuery = parameters.Encode()

	// TODO implement logout business logic here, i.e. invalidate all of the user's tokens

	return logoutURL.String(), nil
}
