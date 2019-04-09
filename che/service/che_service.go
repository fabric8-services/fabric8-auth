package service

import (
	"fmt"
	"context"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/application/service"
	errs "github.com/pkg/errors"
)

// cheServiceImpl is the default implementation of CheService.
type cheServiceImpl struct {
	config Configuration
}

// Configuration the config for the Che service
type Configuration interface {
	GetCheServiceURL() string
}
// NewCheService creates a new Che service.
func NewCheService(config Configuration) service.CheService {
	return &cheServiceImpl{
		config:config,
	}
}

// DeleteUser deletes a user in Che
func (s *cheServiceImpl) DeleteUser(ctx context.Context, identityID string) error {
	log.Info(ctx, map[string]interface{}{"identity_id": identityID}, "deleting user on Che service")
	// this endpoint is restricted to the `auth` Service Account
	deleteUserAPIURL := fmt.Sprintf("%s/api/user/%s", s.config.GetCheServiceURL(), identityID)
	req, err := http.NewRequest("DELETE", deleteUserAPIURL, nil)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "foooo"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID)
	}
	
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to delete user in Che")
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID)
	}
	return nil
}

