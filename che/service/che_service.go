package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	token2 "github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"
)

// cheServiceImpl is the default implementation of CheService.
type cheServiceImpl struct {
	base.BaseService
	config Configuration
}

// Configuration the config for the Che service
type Configuration interface {
	manager.TokenManagerConfiguration
	GetCheServiceURL() string
}

// NewCheService creates a new Che service.
func NewCheService(context servicecontext.ServiceContext, config Configuration) service.CheService {
	return &cheServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// DeleteUser deletes a user in Che
func (s *cheServiceImpl) DeleteUser(ctx context.Context, identity repository.Identity) error {
	log.Info(ctx, map[string]interface{}{"identity_id": identity.ID.String()}, "deleting user on Che service")
	// this endpoint is restricted to the `auth` Service Account
	deleteUserAPIURL := fmt.Sprintf("%s/api/user/%s", s.config.GetCheServiceURL(), identity.ID.String())
	req, err := http.NewRequest("DELETE", deleteUserAPIURL, nil)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identity.ID.String())
	}

	tokenManager, err := manager.DefaultManager(s.config)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identity.ID.String())
	}

	token, err := tokenManager.GenerateTransientUserAccessTokenForIdentity(ctx, identity)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identity.ID.String())
	}

	_, err = s.Services().TokenService().RegisterToken(ctx, identity.ID, *token, token2.TOKEN_TYPE_ACCESS, nil)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identity.ID.String())
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identity.ID.String())
	}

	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks

	switch res.StatusCode {
	case http.StatusNoContent:
		// OK
		return nil
	case http.StatusNotFound:
		// May happen if the user has been already deleted from Che
		// Log the error but return OK
		log.Warn(ctx, map[string]interface{}{
			"identity_id":     identity.ID.String(),
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to delete user in Che which is OK if user already deleted from Che")
		return nil
	}

	log.Error(ctx, map[string]interface{}{
		"identity_id":     identity.ID.String(),
		"response_status": res.Status,
		"response_body":   bodyString,
	}, "unable to delete user in Che")
	return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("unable to delete user '%s' in Che", identity.ID.String()))
}
