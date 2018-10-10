package oauth

import (
	"context"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// OauthConfig represents OAuth2 config
type OauthConfig interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}

// IdentityProvider represents Identity Provider config
type IdentityProvider interface {
	OauthConfig
	Profile(ctx context.Context, token oauth2.Token) (*UserProfile, error)
}

// OauthIdentityProvider is an implementation of Identity Provider
type OauthIdentityProvider struct {
	oauth2.Config
	ProviderID uuid.UUID
	ScopeStr   string
	ProfileURL string
}

// UserProfile represents a user profile fetched from Identity Provider
type UserProfile struct {
	Name          string
	Username      string
	GivenName     string
	FamilyName    string
	Email         string
	EmailVerified bool
	Company       string
	Approved      bool
	Subject       string
}

// UserProfilePayload fetches user profile payload from Identity Provider
func (provider *OauthIdentityProvider) UserProfilePayload(ctx context.Context, token oauth2.Token) ([]byte, error) {
	req, err := http.NewRequest("GET", provider.ProfileURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to create http request")
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to get user profile")
		return nil, err
	}
	defer rest.CloseResponse(res)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to read user profile payload")
		return body, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		log.Error(ctx, map[string]interface{}{
			"status":        res.Status,
			"response_body": string(body),
			"profile_url":   provider.ProfileURL,
		}, "unable to get user profile")
		return nil, errors.NewInternalErrorFromString(ctx, "unable to get user profile")
	}
	return body, nil
}

// SaveReferrer validates referrer and saves it in DB
func SaveReferrer(ctx context.Context, app application.Application, state string, referrer string, responseMode *string, validReferrerURL string) error {
	matched, err := regexp.MatchString(validReferrerURL, referrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"referrer":           referrer,
			"valid_referrer_url": validReferrerURL,
			"err":                err,
		}, "Can't match referrer and whitelist regex")
		return err
	}
	if !matched {
		log.Error(ctx, map[string]interface{}{
			"referrer":           referrer,
			"valid_referrer_url": validReferrerURL,
		}, "Referrer not valid")
		return errors.NewBadParameterError("redirect", "not valid redirect URL")
	}
	// TODO The state reference table will be collecting dead states left from some failed login attempts.
	// We need to clean up the old states from time to time.
	ref := auth.OauthStateReference{
		State:        state,
		Referrer:     referrer,
		ResponseMode: responseMode,
	}

	err = transaction.Transactional(app, func(tr transaction.TransactionalResources) error {
		_, err := tr.OauthStates().Create(ctx, &ref)
		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":         state,
			"referrer":      referrer,
			"response_mode": log.PointerToString(responseMode),
			"err":           err,
		}, "unable to create oauth state reference")
		return err
	}
	return nil
}

// LoadReferrerAndResponseMode loads referrer and responseMode from DB
func LoadReferrerAndResponseMode(ctx context.Context, app application.Application, state string) (string, *string, error) {
	var referrer string
	var responseMode *string

	err := transaction.Transactional(app, func(tr transaction.TransactionalResources) error {
		ref, err := tr.OauthStates().Load(ctx, state)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to load oauth state reference")
			return err
		}
		referrer = ref.Referrer
		responseMode = ref.ResponseMode
		err = tr.OauthStates().Delete(ctx, ref.ID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to delete oauth state reference")
			return err
		}

		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return referrer, responseMode, nil
}
