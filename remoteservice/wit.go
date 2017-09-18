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
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/wit/witservice"
	"github.com/goadesign/goa"
	goaclient "github.com/goadesign/goa/client"
	uuid "github.com/satori/go.uuid"
)

// CreateSecureRemoteWITClient creates a client for sending requests to the remote WIT service.
func CreateSecureRemoteWITClient(ctx context.Context, req *goa.RequestData, remoteEndpoint string, accessToken *string) (*witservice.Client, error) {
	u, err := url.Parse(remoteEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"remote_endpoint": remoteEndpoint,
		}, "unable to parse remote endpoint")
		return nil, err
	}
	witclient := witservice.New(goaclient.HTTPClientDoer(http.DefaultClient))
	witclient.Host = u.Host
	witclient.Scheme = u.Scheme

	if accessToken == nil {
		// if the accessToken is not passed into this function, use the context as is ( which should have the token in it )
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

// CreateSecureRemoteClientAsServiceAccount creates a client that would communicate with WIT service using a service account token.
func CreateSecureRemoteClientAsServiceAccount(ctx context.Context, req *goa.RequestData, remoteEndpoint string) (*witservice.Client, error) {
	u, err := url.Parse(remoteEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"remote_endpoint": remoteEndpoint,
		}, "unable to parse remote endpoint")
		return nil, err
	}
	witclient := witservice.New(goaclient.HTTPClientDoer(http.DefaultClient))
	witclient.Host = u.Host
	witclient.Scheme = u.Scheme

	serviceAccountToken, err := getServiceAccountToken(ctx, req)
	if err != nil {
		return nil, err
	}
	log.Info(ctx, map[string]interface{}{
		"remote_endpoint": remoteEndpoint,
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

// UpdateWITUser updates user in WIT
func UpdateWITUser(ctx context.Context, req *goa.RequestData, updatePayload *app.UpdateUsersPayload, WITEndpoint string, identityID string) error {

	// Designed this method to accept the payload object instead of user/identity objects as arguments
	// so that it's more seamless when we pass it on to WIT. but might be a good idea to pass on
	// user/identity objects just like it's done for CreateWITUser(...)

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

	remoteWITService, err := CreateSecureRemoteClientAsServiceAccount(ctx, req, WITEndpoint)
	remoteUpdateUserAPIPath := witservice.UpdateUserAsServiceAccountUsersPath(identityID)
	_, err = remoteWITService.UpdateUserAsServiceAccountUsers(goasupport.ForwardContextRequestID(ctx), remoteUpdateUserAPIPath, updateUserPayload)
	return err
}

// CreateWITUser updates user in WIT
func CreateWITUser(ctx context.Context, req *goa.RequestData, user *account.User, identity *account.Identity, WITEndpoint string, identityID string) error {
	createUserPayload := &witservice.CreateUserAsServiceAccountUsersPayload{
		Data: &witservice.CreateUserData{
			Attributes: &witservice.CreateIdentityDataAttributes{
				Bio:      &user.Bio,
				Company:  &user.Company,
				Email:    user.Email,
				FullName: &user.FullName,
				ImageURL: &user.ImageURL,
				URL:      &user.URL,
				Username: identity.Username,
				UserID:   identity.User.ID.String(),
			},
			Type: "identities",
		},
	}

	remoteWITService, err := CreateSecureRemoteClientAsServiceAccount(ctx, req, WITEndpoint)
	remoteCreateUserAPIPath := witservice.CreateUserAsServiceAccountUsersPath(identityID)
	_, err = remoteWITService.CreateUserAsServiceAccountUsers(goasupport.ForwardContextRequestID(ctx), remoteCreateUserAPIPath, createUserPayload)
	return err
}

// GetWITUser calls WIT to check if user exists and uses the user's token for authorization and identity ID discovery
func GetWITUser(ctx context.Context, req *goa.RequestData, WITEndpointUserProfile string, accessToken *string) (*account.User, *account.Identity, error) {

	var user *account.User
	var identity *account.Identity

	remoteWITService, err := CreateSecureRemoteWITClient(ctx, req, WITEndpointUserProfile, accessToken)
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
		return nil, nil, nil
	} else {
		// The user is not present in Auth, but present in WIT.
		witServiceUser, _ := remoteWITService.DecodeUser(res)
		id, _ := uuid.FromString(*witServiceUser.Data.ID)
		user = &account.User{
			ID:                 id,
			ContextInformation: witServiceUser.Data.Attributes.ContextInformation,
		}
		if witServiceUser.Data.Attributes.FullName != nil {
			user.FullName = *witServiceUser.Data.Attributes.FullName
		}
		if witServiceUser.Data.Attributes.Email != nil {
			user.Email = *witServiceUser.Data.Attributes.Email
		}
		if witServiceUser.Data.Attributes.ImageURL != nil {
			user.ImageURL = *witServiceUser.Data.Attributes.ImageURL
		}
		if witServiceUser.Data.Attributes.Bio != nil {
			user.Bio = *witServiceUser.Data.Attributes.Bio
		}
		if witServiceUser.Data.Attributes.URL != nil {
			user.URL = *witServiceUser.Data.Attributes.URL
		}
		if witServiceUser.Data.Attributes.Company != nil {
			user.Company = *witServiceUser.Data.Attributes.Company
		}

		identity = &account.Identity{
			ProfileURL: witServiceUser.Data.Attributes.URL,
			UserID:     account.NullUUID{UUID: user.ID, Valid: true},
		}

		if witServiceUser.Data.Attributes.IdentityID != nil {
			identity.ID, err = uuid.FromString(*witServiceUser.Data.Attributes.IdentityID)
			if err != nil {
				return nil, nil, err
			}
		}

		if witServiceUser.Data.Attributes.Username != nil {
			identity.Username = *witServiceUser.Data.Attributes.Username
		}
		if witServiceUser.Data.Attributes.RegistrationCompleted != nil {
			identity.RegistrationCompleted = *witServiceUser.Data.Attributes.RegistrationCompleted
		}
		if witServiceUser.Data.Attributes.ProviderType != nil {
			identity.ProviderType = *witServiceUser.Data.Attributes.ProviderType
		}

	}
	return user, identity, nil
}

func getServiceAccountToken(ctx context.Context, request *goa.RequestData) (string, error) {
	manager, err := token.ReadManagerFromContext(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"error": err,
		}, "unable to obtain service token")
		return "", err
	}
	return (*manager).ServiceAccountToken(request)
}
