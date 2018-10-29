package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"net/http"

	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	errs "github.com/pkg/errors"
)

type SignUpNeededError struct {
	Err error
}

func (e SignUpNeededError) Error() string {
	return e.Err.Error()
}

func newSignUpNeededError(ctx context.Context, err error) SignUpNeededError {
	return SignUpNeededError{err}
}

func IsSignUpNeededError(err error) bool {
	_, ok := errs.Cause(err).(SignUpNeededError)
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

type RemoteSubscriptionLoaderConfiguration interface {
	GetOSORegistrationAppURL() string
	GetOSORegistrationAppAdminUsername() string
	GetOSORegistrationAppAdminToken() string
}

type remoteSubscriptionLoader struct {
	config     RemoteSubscriptionLoaderConfiguration
	httpClient *http.Client
}

func NewRemoteSubscriptionLoader(config RemoteSubscriptionLoaderConfiguration) SubscriptionLoader {
	return &remoteSubscriptionLoader{
		config:     config,
		httpClient: http.DefaultClient,
	}
}

func (l *remoteSubscriptionLoader) LoadSubscriptions(ctx context.Context, username string) (*Subscriptions, error) {
	// Load status from OSO
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/subscriptions?authorization_username=%s",
		l.config.GetOSORegistrationAppURL(), username, l.config.GetOSORegistrationAppAdminUsername())

	req, err := http.NewRequest("GET", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return nil, autherrors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+l.config.GetOSORegistrationAppAdminToken())
	res, err := l.httpClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
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
			"body":        bodyString,
		}, "unable to unmarshal json with subscription status")
		return nil, autherrors.NewInternalError(ctx, err)
	}

	return &sbs, nil
}
