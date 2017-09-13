package remoteservice

import (
	"context"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/wit/witservice"
	goaclient "github.com/goadesign/goa/client"
	uuid "github.com/satori/go.uuid"
)

// CreateSecureRemoteWITClient creates a client for sending requests to the remote WIT service. Pass nil for accessToken if you wish to
// use the token in the context.
func CreateSecureRemoteWITClient(ctx context.Context, remoteEndpoint string, accessToken *string) (*witservice.Client, error) {
	u, err := url.Parse(remoteEndpoint)
	if err != nil {
		return nil, err
	}
	witclient := witservice.New(goaclient.HTTPClientDoer(http.DefaultClient))
	witclient.Host = u.Host
	witclient.Scheme = u.Scheme

	if accessToken == nil {
		witclient.SetJWTSigner(goasupport.NewForwardSigner(ctx))
		return witclient, nil
	}
	staticToken := goaclient.StaticToken{
		Value: *accessToken,
	}
	jwtSigner := goaclient.JWTSigner{
		TokenSource: &goaclient.StaticTokenSource{
			StaticToken: &staticToken,
		},
	}
	witclient.SetJWTSigner(&jwtSigner)
	return witclient, nil
}

// UpdateWITUser updates user in WIT
func UpdateWITUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, WITEndpoint string, accessToken *string) error {
	updateUserPayload := &witservice.UpdateUsersPayload{
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

	remoteWITService, err := CreateSecureRemoteWITClient(ctx, WITEndpoint, accessToken)
	remoteUpdateUserAPIPath := witservice.UpdateUsersPath()
	_, err = remoteWITService.UpdateUsers(goasupport.ForwardContextRequestID(ctx), remoteUpdateUserAPIPath, updateUserPayload)
	return err
}

// GetWITUser calls WIT to check if user exists.
func GetWITUser(ctx context.Context, WITEndpointUserProfile string, accessToken *string) (*account.User, *account.Identity, error) {
	/*
	 Call WIT API to see if user is already present there.
	*/
	var user *account.User
	var identity *account.Identity

	remoteWITService, err := CreateSecureRemoteWITClient(ctx, WITEndpointUserProfile, accessToken)
	res, err := remoteWITService.ShowUser(goasupport.ForwardContextRequestID(ctx), witservice.ShowUserPath(), nil, nil)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			// This means its a new user who is logging in.
			log.Error(ctx, map[string]interface{}{
				"response_status": res.Status,
				"response_body":   rest.ReadBody(res.Body),
			}, "unable to fetch user via wit service, looks like a new user")
		}
	} else {
		// The user is not present in Auth, but present in WIT.
		witServiceUser, _ := remoteWITService.DecodeUser(res)
		id, _ := uuid.FromString(*witServiceUser.Data.ID)
		user = &account.User{
			FullName:           *witServiceUser.Data.Attributes.FullName,
			ID:                 id,
			Email:              *witServiceUser.Data.Attributes.Email,
			ImageURL:           *witServiceUser.Data.Attributes.ImageURL,
			Bio:                *witServiceUser.Data.Attributes.Bio,
			URL:                *witServiceUser.Data.Attributes.URL,
			Company:            *witServiceUser.Data.Attributes.Company,
			ContextInformation: witServiceUser.Data.Attributes.ContextInformation,
		}
		identity = &account.Identity{
			Username:              *witServiceUser.Data.Attributes.Username,
			RegistrationCompleted: *witServiceUser.Data.Attributes.RegistrationCompleted,
			ProfileURL:            witServiceUser.Data.Attributes.URL,
			ProviderType:          *witServiceUser.Data.Attributes.ProviderType,
			UserID:                account.NullUUID{UUID: user.ID, Valid: true},
		}

	}
	return user, identity, nil
}
