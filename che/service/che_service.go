package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	errs "github.com/pkg/errors"
)

// cheServiceImpl is the default implementation of CheService.
type cheServiceImpl struct {
	base.BaseService
	config       Configuration
	tokenManager manager.TokenManager
}

// Configuration the config for the Che service
type Configuration interface {
	manager.TokenManagerConfiguration
	GetCheServiceURL() string
}

// NewCheService creates a new Che service.
func NewCheService(context servicecontext.ServiceContext, config Configuration) service.CheService {
	tokenManager, err := manager.NewTokenManager(config)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to create token manager")
	}

	return &cheServiceImpl{
		BaseService:  base.NewBaseService(context),
		config:       config,
		tokenManager: tokenManager,
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

	identity, err := s.Repositories().Identities().Load(ctx, identityID)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID)
	}

	token, err := s.tokenManager.GenerateTransientAccessTokenForIdentity(ctx, identity)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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
