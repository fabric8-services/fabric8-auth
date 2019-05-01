package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const signUpNeededStatus = "signup_needed"

// OSOSubscriptionServiceConfiguration the OSOSubscriptionService implementation configuration
type OSOSubscriptionServiceConfiguration interface {
	// manager.TokenManagerConfiguration
	GetOSORegistrationAppURL() string
	GetOSORegistrationAppAdminUsername() string
	GetOSORegistrationAppAdminToken() string
}

type osoSubscriptionServiceImpl struct {
	base.BaseService
	config     OSOSubscriptionServiceConfiguration
	httpClient rest.HttpClient
}

// NewOSOSubscriptionService returns a new OSOSubscriptionService implementation
func NewOSOSubscriptionService(context servicecontext.ServiceContext, config OSOSubscriptionServiceConfiguration) service.OSOSubscriptionService {
	return &osoSubscriptionServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
		httpClient:  http.DefaultClient,
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

	subs, err := s.loadSubscriptions(ctx, username)
	if err != nil {
		if isSignUpNeededError(err) {
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

type signUpNeededError struct {
	Err error
}

func (e signUpNeededError) Error() string {
	return e.Err.Error()
}

func newSignUpNeededError(ctx context.Context, err error) signUpNeededError {
	return signUpNeededError{err}
}

func isSignUpNeededError(err error) bool {
	_, ok := errs.Cause(err).(signUpNeededError)
	if !ok {
		return false
	}
	return true
}

type Subscriptions struct {
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

type SubscriptionLoader interface {
	LoadSubscriptions(ctx context.Context, username string) (*Subscriptions, error)
}

func (s *osoSubscriptionServiceImpl) loadSubscriptions(ctx context.Context, username string) (*Subscriptions, error) {
	// Load status from OSO
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/subscriptions?authorization_username=%s",
		s.config.GetOSORegistrationAppURL(), username, s.config.GetOSORegistrationAppAdminUsername())
	log.Debug(ctx, map[string]interface{}{
		"url": regAppURL,
	}, "calling remote registration application to check the user status")
	req, err := http.NewRequest("GET", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"username":    username,
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return nil, autherrors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", s.config.GetOSORegistrationAppAdminToken()))
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"username":    username,
			"reg_app_url": regAppURL,
		}, "unable to load OSO subscription status")
		return nil, autherrors.NewInternalError(ctx, err)
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			// User does not exist
			return nil, newSignUpNeededError(ctx, nil)
		}

		log.Error(ctx, map[string]interface{}{
			"reg_app_url":     regAppURL,
			"username":        username,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to load OSO subscription status")
		return nil, autherrors.NewInternalError(ctx, errors.New("unable to load OSO subscription status"))
	}

	var sbs Subscriptions
	err = json.Unmarshal([]byte(bodyString), &sbs)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"reg_app_url": regAppURL,
			"username":    username,
			"body":        bodyString,
		}, "unable to unmarshal json with subscription status")
		return nil, autherrors.NewInternalError(ctx, err)
	}

	return &sbs, nil
}

// DeactivateUser deactivates the user on OpenShift Online
func (s *osoSubscriptionServiceImpl) DeactivateUser(ctx context.Context, username string) error {
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/deprovision_osio?authorization_username=%s",
		s.config.GetOSORegistrationAppURL(), username, s.config.GetOSORegistrationAppAdminUsername())
	log.Info(ctx, map[string]interface{}{
		"reg_app_url": regAppURL,
		"username":    username,
	}, "calling remote registration application to deactivate user")
	req, err := http.NewRequest("POST", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return errs.Wrapf(err, "unable to deprovision user")
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", s.config.GetOSORegistrationAppAdminToken()))
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to deprovision user")
		return errs.Wrapf(err, "unable to deprovision user")
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {
		log.Error(ctx, map[string]interface{}{
			"reg_app_url":     regAppURL,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to deprovision user")
		return errs.Errorf("unable to deprovision user")
	}
	return nil
}
