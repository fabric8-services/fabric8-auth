package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"golang.org/x/oauth2"
	"net/http"

	autherrors "github.com/fabric8-services/fabric8-auth/errors"
)

const signUpNeededStatus = "signup_needed"

type OSOSubscriptionServiceConfiguration interface {
	token.TokenConfiguration
	GetOSORegistrationAppURL() string
	GetOSORegistrationAppAdminUsername() string
	GetOSORegistrationAppAdminToken() string
}

type subscriptions struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

type Subscription struct {
	Status string `json:"status"`
	Plan   Plan   `json:"plan"`
}

type Plan struct {
	Service Service `json:"service"`
}

type Service struct {
	APIURL string `json:"api_url"`
}

type osoSubscriptionServiceImpl struct {
	base.BaseService
	config       OSOSubscriptionServiceConfiguration
	tokenManager token.Manager
	httpClient   rest.HttpClient
}

func NewOSOSubscriptionService(context servicecontext.ServiceContext, config OSOSubscriptionServiceConfiguration) service.OSOSubscriptionService {
	tokenManager, err := token.NewManager(config)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to create token manager")
	}

	return &osoSubscriptionServiceImpl{
		BaseService:  base.NewBaseService(context),
		config:       config,
		tokenManager: tokenManager,
		httpClient:   http.DefaultClient,
	}
}

// LoadOSOSubscriptionStatus loads a subscription status from OpenShift Online Registration app
func (s *osoSubscriptionServiceImpl) LoadOSOSubscriptionStatus(ctx context.Context, token oauth2.Token) (string, error) {

	// Extract username from the token
	tokenClaims, err := s.tokenManager.ParseToken(ctx, token.AccessToken)
	if err != nil {
		return "", err
	}
	username := tokenClaims.Username

	// Load status from OSO
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/subscriptions?authorization_username=%s", s.config.GetOSORegistrationAppURL(), username, s.config.GetOSORegistrationAppAdminUsername())

	req, err := http.NewRequest("GET", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return "", autherrors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+s.config.GetOSORegistrationAppAdminToken())
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to load OSO subscription status")
		return "", autherrors.NewInternalError(ctx, err)
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			// User does not exist
			return signUpNeededStatus, nil
		}

		log.Error(ctx, map[string]interface{}{
			"reg_app_url":     regAppURL,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to load OSO subscription status")
		return "", autherrors.NewInternalError(ctx, errors.New("unable to load OSO subscription status"))
	}

	var sbs subscriptions
	err = json.Unmarshal([]byte(bodyString), &sbs)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"reg_app_url": regAppURL,
			"body":        bodyString,
		}, "unable to unmarshal json with subscription status")
		return "", autherrors.NewInternalError(ctx, err)
	}

	for _, subscription := range sbs.Subscriptions {
		cluster, err := s.Services().ClusterService().ClusterByURL(ctx, subscription.Plan.Service.APIURL)
		if err != nil {
			return "", autherrors.NewInternalError(ctx, err)
		}
		if cluster != nil {
			return subscription.Status, nil
		}
	}
	// Didn't find subscription for OSIO clusters. OSIO sign up is required.
	return signUpNeededStatus, nil
}
