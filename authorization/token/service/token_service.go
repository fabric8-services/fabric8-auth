package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	tokenPkg "github.com/fabric8-services/fabric8-auth/authorization/token"
		"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"

	"github.com/fabric8-services/fabric8-auth/login"
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
// Returns an empty string if no new token has been issued, otherwise returns the new token string
func (s *tokenServiceImpl) Audit(ctx context.Context, tokenString string, resourceID string) (string, error) {

	// First let's make sure we can load the identity from the context
	identity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, s.Repositories())
	if err != nil {
		return "", err
	}

	// Get the token manager from the context
	tm := tokencontext.ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return "", errors.NewInternalErrorFromString(ctx, "Missing token manager")
	}
	manager := tm.(token.Manager)

	// Now parse the token string that was passed in
	jwtToken, err := manager.Parse(ctx, tokenString)
	if err != nil {
		return "", errors.NewBadParameterErrorFromString("tokenString", tokenString, "invalid token string could not be parsed")
	}

	// Now that we have the identity and have parsed the token, we can see if we have a record of the token in the database
	var tokenID uuid.UUID

	if claims, ok := jwtToken.Claims.(jwt.StandardClaims); ok {
		tokenID, err = uuid.FromString(claims.Id)
		if err != nil {
			// TODO Ignore? or perhaps log
		}
	} else {
		// TODO work out what to do here
	}

	token, err := s.Repositories().TokenRepository().Load(ctx, tokenID)
	if err != nil {
		// This is not an error per se, so we'll just log an informational message
		log.Info(ctx, map[string]interface{}{
			"token_id": tokenID,
		}, "token with specified id not found")
	}

	if token != nil {
		// Confirm that the token belongs to the current identity
		if token.IdentityID != identity.ID {
			return "", errors.NewUnauthorizedError("invalid token for identity")
		}

		// If the token exists and its status is valid, return it
		if token.Valid() {
			return "", nil
		}

		// We now process the various token status codes in order of priority, starting with DEPROVISIONED
		if token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED) {
			// return a WWW-Authenticate: DEPROVISIONED response
			// TODO adjust this error return code
			return "", errors.NewInternalError(ctx, nil)
		}

		// If the token has been revoked or the user is logged out, we respond in the same way
		if token.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED) || token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT) {
			// return a WWW-Authenticate: LOGIN response
			// TODO adjust this error return code
			return "", errors.NewInternalError(ctx, nil)
		}

		// If the token is stale, we can re-evaluate its privileges to determine whether they have changed
		if token.HasStatus(tokenPkg.TOKEN_STATUS_STALE) {
			// Query for all of the token's privileges
			privileges, err := s.Repositories().TokenRepository().ListPrivileges(ctx, tokenID)
			if err != nil {
				return "", errors.NewInternalError(ctx, err)
			}

			// First we recalculate any stale privileges
			for _, priv := range privileges {
				if priv.Stale {
					/*scopes*/_, err := s.Services().PrivilegeCacheService().ScopesForResource(ctx, priv.IdentityID, priv.ResourceID)
					if err != nil {
						return "", errors.NewInternalError(ctx, err)
					}

					// Compare the returned scopes with those in the token

				}
			}

			// Now we compare all privileges to those contained in the current token
		}
	}

	// If we've gotten this far, it means that either no existing token was found, or the token that was found
	// has been marked with status STALE and its privileges have changed, in either case we must generate a new token

	// TODO new token generation

	return "", nil
}

func (s *tokenServiceImpl) generateNewToken(ctx context.Context, identityID uuid.UUID, resourceID string) (*jwt.Token, error) {
	return nil, nil

}
