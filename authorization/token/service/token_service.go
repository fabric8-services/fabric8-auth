package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"github.com/fabric8-services/fabric8-auth/login"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
			"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"github.com/fabric8-services/fabric8-auth/log"
)

type tokenServiceImpl struct {
	base.BaseService
}

func NewTokenService(context servicecontext.ServiceContext) service.TokenService {
	return &tokenServiceImpl{
		BaseService: base.NewBaseService(context),
	}
}

// Audit verifies an existing token in respect to its privileges for a specified resource.  It starts by validating
// the status of the token passed in the request, and if that token is currently valid and contains the specified
// resource, returns the same token.  If the token is invalid or outdated, or doesn't contain the specified resource,
// then a new token is generated and returned.
func (s *tokenServiceImpl) Audit(ctx context.Context, tokenString string, resourceID string) (bool, string, error) {



	// First let's load the identity
	identity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, s.Repositories())


	// The first thing this function does is validate the token that was passed in
	var tokenID uuid.UUID
	var err error

	if claims, ok := token.Claims.(jwt.StandardClaims); ok  {
		tokenID, err = uuid.FromString(claims.Id)
		if err != nil {
			// Ignore? or perhaps log
		}
	} else {
		// If we can't succeed in
	}

	rptToken, err := s.Repositories().RPTTokenRepository().Load(ctx, tokenID)
	if err != nil {
		// This is not an error per se, so we'll just log an informational message
		log.Info(ctx, map[string]interface{}{
			"token_id":        tokenID,
		}, "token with specified id not found")
	} else {
		// If the token exists and its status is valid, return it
		if rptToken.Valid() {
			return token, nil
		} else {
			// If the status is invalid, we need to generate a new token.
		}
	}

	// If we've gotten this far, it means we must generate a new token




	return nil, nil
}

func (s *tokenServiceImpl) generateNewToken(ctx context.Context, identityID uuid.UUID, resourceID string) (*jwt.Token, error) {

}