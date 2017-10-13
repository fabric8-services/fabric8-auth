package oauth

import (
	"context"
	"regexp"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// OauthConfig represents OAuth2 config
type OauthConfig interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}

// SaveReferrer validates referrer and saves it in DB
func SaveReferrer(ctx context.Context, db application.DB, state uuid.UUID, referrer string, validReferrerURL string) error {
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
		ID:       state,
		Referrer: referrer,
	}
	err = application.Transactional(db, func(appl application.Application) error {
		_, err := appl.OauthStates().Create(ctx, &ref)
		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":    state,
			"referrer": referrer,
			"err":      err,
		}, "unable to create oauth state reference")
		return err
	}
	return nil
}

// LoadReferrer loads referrer from DB
func LoadReferrer(ctx context.Context, db application.DB, state string) (string, error) {
	var referrer string
	stateID, err := uuid.FromString(state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "unable to convert oauth state to uuid")
		return "", err
	}
	err = application.Transactional(db, func(appl application.Application) error {
		ref, err := appl.OauthStates().Load(ctx, stateID)
		if err != nil {
			return err
		}
		referrer = ref.Referrer
		err = appl.OauthStates().Delete(ctx, stateID)
		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "unable to delete oauth state reference")
		return "", err
	}
	return referrer, nil
}
