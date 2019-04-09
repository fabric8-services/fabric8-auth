package service

import (
	"context"
	"fmt"
	token2 "github.com/fabric8-services/fabric8-auth/authorization/token"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
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
func (s *cheServiceImpl) DeleteUser(ctx context.Context, identityID uuid.UUID) error {
	log.Info(ctx, map[string]interface{}{"identity_id": identityID.String()}, "deleting user on Che service")
	// this endpoint is restricted to the `auth` Service Account
	deleteUserAPIURL := fmt.Sprintf("%s/api/user/%s", s.config.GetCheServiceURL(), identityID.String())
	req, err := http.NewRequest("DELETE", deleteUserAPIURL, nil)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}

	identity, err := s.Repositories().Identities().Load(ctx, identityID)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}

	token, err := s.Services().TokenService().TokenManager().GenerateTransientUserAccessTokenForIdentity(ctx, *identity)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}

	_, err = s.Services().TokenService().RegisterToken(ctx, identityID, *token, token2.TOKEN_TYPE_ACCESS, nil)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}

	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID.String(),
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to delete user in Che")
		return errs.Wrapf(err, "unable to delete user '%s' in Che", identityID.String())
	}
	return nil
}
