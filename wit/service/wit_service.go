package service

import (
	"context"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/authorization/token/signer"

	"github.com/fabric8-services/fabric8-auth/app"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/wit/witservice"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"github.com/fabric8-services/fabric8-auth/wit"
	"github.com/goadesign/goa/uuid"
	"github.com/pkg/errors"
)

// witServiceImpl is the default implementation of WITService.
type witServiceImpl struct {
	base.BaseService
	config wit.Configuration
	doer   rest.HttpDoer
}

// NewWITService creates a new WIT service.
func NewWITService(context servicecontext.ServiceContext, config wit.Configuration) service.WITService {
	return &witServiceImpl{base.NewBaseService(context), config, rest.DefaultHttpDoer()}
}

// UpdateUser updates user in WIT
func (s *witServiceImpl) UpdateUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, identityID string) error {
	// Using the UpdateUserPayload because it also describes which attribtues are being updated and which are not.
	updateUserPayload := &witservice.UpdateUserAsServiceAccountUsersPayload{
		Data: &witservice.UpdateUserData{
			Attributes: &witservice.UpdateIdentityDataAttributes{
				Bio:                   updatePayload.Data.Attributes.Bio,
				Company:               updatePayload.Data.Attributes.Company,
				ContextInformation:    updatePayload.Data.Attributes.ContextInformation,
				Email:                 updatePayload.Data.Attributes.Email,
				FullName:              updatePayload.Data.Attributes.FullName,
				ImageURL:              updatePayload.Data.Attributes.ImageURL,
				RegistrationCompleted: updatePayload.Data.Attributes.RegistrationCompleted,
				URL:      updatePayload.Data.Attributes.URL,
				Username: updatePayload.Data.Attributes.Username,
			},
			Type: updatePayload.Data.Type,
		},
	}

	remoteWITService, err := s.createClientWithContextSigner(ctx)

	if err != nil {
		return err
	}

	remoteUpdateUserAPIPath := witservice.UpdateUserAsServiceAccountUsersPath(identityID)
	res, err := remoteWITService.UpdateUserAsServiceAccountUsers(goasupport.ForwardContextRequestID(ctx), remoteUpdateUserAPIPath, updateUserPayload)
	if err != nil {
		return err
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID,
			"username":        updatePayload.Data.Attributes.Username,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to update user in WIT")
		return errors.Errorf("unable to update user in WIT. Response status: %s. Response body: %s", res.Status, bodyString)
	}
	return nil
}

// CreateUser creates a new user in WIT
func (s *witServiceImpl) CreateUser(ctx context.Context, identity *account.Identity, identityID string) error {
	createUserPayload := &witservice.CreateUserAsServiceAccountUsersPayload{
		Data: &witservice.CreateUserData{
			Attributes: &witservice.CreateIdentityDataAttributes{
				Bio:          &identity.User.Bio,
				Company:      &identity.User.Company,
				Email:        identity.User.Email,
				FullName:     &identity.User.FullName,
				ImageURL:     &identity.User.ImageURL,
				URL:          &identity.User.URL,
				Username:     identity.Username,
				UserID:       identity.User.ID.String(),
				ProviderType: identity.ProviderType,
			},
			Type: "identities",
		},
	}

	remoteWITService, err := s.createClientWithContextSigner(ctx)
	if err != nil {
		return err
	}
	remoteCreateUserAPIPath := witservice.CreateUserAsServiceAccountUsersPath(identityID)
	res, err := remoteWITService.CreateUserAsServiceAccountUsers(goasupport.ForwardContextRequestID(ctx), remoteCreateUserAPIPath, createUserPayload)
	if err != nil {
		return err
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID,
			"username":        identity.Username,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to create user in WIT")
		return errors.Errorf("unable to create user in WIT. Response status: %s. Response body: %s", res.Status, bodyString)
	}
	return nil

}

// GetSpace talks to the WIT service to retrieve a space record for the specified spaceID, then returns space
func (s *witServiceImpl) GetSpace(ctx context.Context, spaceID string) (space *wit.Space, e error) {
	remoteWITService, err := s.createClientWithContextSigner(ctx)
	if err != nil {
		return nil, err
	}

	spaceIDUUID, err := uuid.FromString(spaceID)
	if err != nil {
		return nil, err
	}

	res, err := remoteWITService.ShowSpace(ctx, witservice.ShowSpacePath(spaceIDUUID), nil, nil)
	if err != nil {
		return nil, err
	}

	defer rest.CloseResponse(res)
	if res.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(res.Body)
		log.Error(ctx, map[string]interface{}{
			"spaceId":         spaceID,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to get space from WIT")
		return nil, errors.Errorf("unable to get space from WIT. Response status: %s. Response body: %s", res.Status, bodyString)
	}

	spaceSingle, err := remoteWITService.DecodeSpaceSingle(res)
	if err != nil {
		return nil, err
	}

	return &wit.Space{
		ID:          *spaceSingle.Data.ID,
		Name:        *spaceSingle.Data.Attributes.Name,
		Description: *spaceSingle.Data.Attributes.Description,
		OwnerID:     *spaceSingle.Data.Relationships.OwnedBy.Data.ID}, nil
}

// createClientWithContextSigner creates with a signer based on current context
func (s *witServiceImpl) createClientWithContextSigner(ctx context.Context) (*witservice.Client, error) {
	c, err := s.createClient()
	if err != nil {
		return nil, err
	}
	sgn := signer.NewSATokenSigner(ctx)
	saTokenSigner, err := sgn.Signer()
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(saTokenSigner)
	return c, nil
}

func (s *witServiceImpl) createClient() (*witservice.Client, error) {
	witURL, e := s.config.GetWITURL()
	if e != nil {
		return nil, e
	}
	u, err := url.Parse(witURL)
	if err != nil {
		return nil, err
	}

	c := witservice.New(s.doer)
	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
