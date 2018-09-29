package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"

	"golang.org/x/oauth2"
)

const signUpNeededStatus = "signup_needed"

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

type OSOSubscriptionManager interface {
	LoadOSOSubscriptionStatus(ctx context.Context, config Configuration, keycloakToken oauth2.Token) (string, error)
}

type osoRegistrationApp struct {
	httpClient rest.HttpClient
	App        application.Application
}

// NewOSORegistrationApp constructs a new OSOSubscriptionManager with default HTTP Client
func NewOSORegistrationApp(app application.Application) OSOSubscriptionManager {
	return &osoRegistrationApp{
		httpClient: http.DefaultClient,
		App:        app,
	}
}

func NewOSORegistrationAppWithClient(client rest.HttpClient, app application.Application) OSOSubscriptionManager {
	return &osoRegistrationApp{
		httpClient: client,
		App:        app,
	}
}

// LoadOSOSubscriptionStatus loads a subscription status from OpenShift Online Registration app
func (regApp *osoRegistrationApp) LoadOSOSubscriptionStatus(ctx context.Context, config Configuration, keycloakToken oauth2.Token) (string, error) {

	// Extract username from the token
	tokenManager, err := token.ReadManagerFromContext(ctx)
	if err != nil {
		return "", err
	}
	tokenClaims, err := tokenManager.ParseToken(ctx, keycloakToken.AccessToken)
	if err != nil {
		return "", err
	}
	username := tokenClaims.Username

	// Load status from OSO
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/subscriptions?authorization_username=%s", config.GetOSORegistrationAppURL(), username, config.GetOSORegistrationAppAdminUsername())

	req, err := http.NewRequest("GET", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return "", autherrors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+config.GetOSORegistrationAppAdminToken())
	res, err := regApp.httpClient.Do(req)
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
		cluster, err := regApp.App.ClusterService().ClusterByURL(ctx, subscription.Plan.Service.APIURL)
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
