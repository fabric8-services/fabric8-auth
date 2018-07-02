package wit

import (
	"context"
	"net/http"
	"net/url"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/wit/witservice"

	goaclient "github.com/goadesign/goa/client"
	"github.com/pkg/errors"
)

// RemoteWITService specifies the behaviour of a remote WIT caller
type RemoteWITService interface {
	UpdateWITUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, witURL string, identityID string) error
	CreateWITUser(ctx context.Context, identity *account.Identity, witURL string, identityID string) error
}

type RemoteWITServiceCaller struct{}

// UpdateWITUser updates user in WIT
func (r *RemoteWITServiceCaller) UpdateWITUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, witURL string, identityID string) error {

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
func (r *RemoteWITServiceCaller) CreateWITUser(ctx context.Context, identity *account.Identity, witURL string, identityID string) error {
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
	return nil

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
