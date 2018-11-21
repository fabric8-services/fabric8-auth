package service

import (
	"context"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/subscription"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"golang.org/x/oauth2"

	autherrors "github.com/fabric8-services/fabric8-auth/errors"
)

const signUpNeededStatus = "signup_needed"

type OSOSubscriptionServiceConfiguration interface {
	manager.TokenManagerConfiguration
	GetOSORegistrationAppURL() string
	GetOSORegistrationAppAdminUsername() string
	GetOSORegistrationAppAdminToken() string
}

type osoSubscriptionServiceImpl struct {
	base.BaseService
	config       OSOSubscriptionServiceConfiguration
	httpClient   rest.HttpClient
}

func NewOSOSubscriptionService(context servicecontext.ServiceContext, config OSOSubscriptionServiceConfiguration) service.OSOSubscriptionService {
	return &osoSubscriptionServiceImpl{
		BaseService:  base.NewBaseService(context),
		config:       config,
		httpClient:   http.DefaultClient,
	}
}

// LoadOSOSubscriptionStatus loads a subscription status from OpenShift Online Registration app
func (s *osoSubscriptionServiceImpl) LoadOSOSubscriptionStatus(ctx context.Context, token oauth2.Token) (string, error) {

	tm, err := manager.ReadTokenManagerFromContext(ctx)
	if err != nil {
		log.Error(nil, map[string]interface{}{
				"err": err,
		}, "failed to create token manager")
		return "", autherrors.NewInternalError(ctx, err)
	}

	// Extract username from the token
	tokenClaims, err := tm.ParseToken(ctx, token.AccessToken)
	if err != nil {
		return "", err
	}
	username := tokenClaims.Username

	subs, err := s.Factories().SubscriptionLoaderFactory().NewSubscriptionLoader(ctx).LoadSubscriptions(ctx, username)
	if err != nil {
		if subscription.IsSignUpNeededError(err) {
			return signUpNeededStatus, nil
		}
		return "", autherrors.NewInternalError(ctx, err)
	}

	for _, sub := range subs.Subscriptions {
		cluster, err := s.Services().ClusterService().ClusterByURL(ctx, sub.Plan.Service.APIURL)
		if err != nil {
			return "", autherrors.NewInternalError(ctx, err)
		}
		if cluster != nil {
			return sub.Status, nil
		}
	}
	// Didn't find subscription for OSIO clusters. OSIO sign up is required.
	return signUpNeededStatus, nil
}
