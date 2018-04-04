package login

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
)

type OSOSubscriptionManager interface {
	LoadOSOSubscriptionStatus(ctx context.Context, request goa.RequestData, config Configuration, keycloakToken oauth2.Token) (string, error)
}

type OSORegistrationApp struct {
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

func (regApp *OSORegistrationApp) LoadOSOSubscriptionStatus(ctx context.Context, request goa.RequestData, config Configuration, keycloakToken oauth2.Token) (string, error) {
	username := "loadFromToken"
	regAppURL := fmt.Sprintf("%s/api/accounts/%s/subscriptions?authorization_username=%s", config.GetOSORegistrationAppURL(), username, config.GetOSORegistrationAppAdminUsername())

	req, err := http.NewRequest("GET", regAppURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to create http request")
		return "", errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+config.GetOSORegistrationAppAdminToken())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"reg_app_url": regAppURL,
		}, "unable to load OSO subscription status")
		return "", errors.NewInternalError(ctx, err)
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)

	var sbs subscriptions
	err = json.Unmarshal([]byte(bodyString), &sbs)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"reg_app_url": regAppURL,
			"body":        bodyString,
		}, "unable to unmarshal json with subscription status")
		return "", errors.NewInternalError(ctx, err)
	}

	for _, subscription := range sbs.Subscriptions {
		if config.GetOSOClusterByURL(subscription.Plan.Service.APIURL) != nil {
			return subscription.Status, nil
		}
	}
	log.Error(ctx, map[string]interface{}{
		"reg_app_url": regAppURL,
		"body":        bodyString,
	}, "unable to find subscription status for any known cluster")
	return "", errors.NewInternalError(ctx, err)
}
