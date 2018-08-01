package service

import (
	"context"
	"net/http"
	"net/url"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/wit/witservice"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"github.com/fabric8-services/fabric8-auth/wit"
	goaclient "github.com/goadesign/goa/client"
	"github.com/goadesign/goa/uuid"
	"github.com/pkg/errors"
)

// witServiceImpl is the default implementation of WITService.
type witServiceImpl struct {
	base.BaseService
	config wit.Configuration
}

// NewWITService creates a new WIT service.
func NewWITService(context servicecontext.ServiceContext, config wit.Configuration) service.WITService {
	return &witServiceImpl{base.NewBaseService(context), config}
}

// UpdateWITUser updates user in WIT
func (r *witServiceImpl) UpdateWITUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, identityID string) error {
	witURL, e := r.config.GetWITURL()
	if e != nil {
		return e
	}

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

	remoteWITService, err := CreateSecureRemoteClientAsServiceAccount(ctx, witURL)

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

// CreateWITUser creates a new user in WIT
func (r *witServiceImpl) CreateWITUser(ctx context.Context, identity *account.Identity, identityID string) error {
	witURL, e := r.config.GetWITURL()
	if e != nil {
		return e
	}

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

	remoteWITService, err := CreateSecureRemoteClientAsServiceAccount(ctx, witURL)
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
		return errors.Errorf("unable to update user in WIT. Response status: %s. Response body: %s", res.Status, bodyString)
	}
	return err

}

// GetSpace talks to the WIT service to retrieve a space record for the specified spaceID, then returns space
func (r *witServiceImpl) GetSpace(ctx context.Context, spaceID string) (space wit.Space, e error) {
	witURL, err := r.config.GetWITURL()
	var s wit.Space
	if err != nil {
		return s, err
	}
	remoteWITService, err := CreateSecureRemoteClientAsServiceAccount(ctx, witURL)
	if err != nil {
		return s, err
	}

	spaceIDUUID, err := uuid.FromString(spaceID)
	if err != nil {
		return s, err
	}

	response, err := remoteWITService.ShowSpace(ctx, witservice.ShowSpacePath(spaceIDUUID), nil, nil)
	if err != nil {
		return s, err
	}

	spaceSingle, err := remoteWITService.DecodeSpaceSingle(response)
	if err != nil {
		return s, err
	}

	return wit.Space{
		ID:          *spaceSingle.Data.ID,
		Name:        *spaceSingle.Data.Attributes.Name,
		Description: *spaceSingle.Data.Attributes.Description,
		OwnerID:     *spaceSingle.Data.Relationships.OwnedBy.Data.ID}, nil
}

// CreateSecureRemoteClientAsServiceAccount creates a client that would communicate with WIT service using a service account token.
func CreateSecureRemoteClientAsServiceAccount(ctx context.Context, remoteURL string) (*witservice.Client, error) {
	u, err := url.Parse(remoteURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"remote_url": remoteURL,
			"err":        err,
		}, "unable to parse remote endpoint")
		return nil, err
	}
	witclient := witservice.New(goaclient.HTTPClientDoer(http.DefaultClient))
	witclient.Host = u.Host
	witclient.Scheme = u.Scheme

	serviceAccountToken, err := getServiceAccountToken(ctx)
	if err != nil {
		return nil, err
	}
	log.Info(ctx, map[string]interface{}{
		"remote_url": remoteURL,
	}, "service token generated, will be used to call WIT")
	staticToken := goaclient.StaticToken{
		Value: serviceAccountToken,
	}
	jwtSigner := goaclient.JWTSigner{
		TokenSource: &goaclient.StaticTokenSource{
			StaticToken: &staticToken,
		},
	}
	witclient.SetJWTSigner(&jwtSigner)
	return witclient, nil
}

func getServiceAccountToken(ctx context.Context) (string, error) {
	manager, err := token.ReadManagerFromContext(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"error": err,
		}, "unable to obtain service token")
		return "", err
	}
	return (*manager).AuthServiceAccountToken(), nil
}
