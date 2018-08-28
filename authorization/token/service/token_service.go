package service

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	tokenPkg "github.com/fabric8-services/fabric8-auth/authorization/token"
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/satori/go.uuid"

	"sort"
	"time"
)

type TokenServiceConfiguration interface {
	GetRPTTokenMaxPermissions() int
}

type tokenServiceImpl struct {
	base.BaseService
	config TokenServiceConfiguration
}

func NewTokenService(context servicecontext.ServiceContext, conf TokenServiceConfiguration) service.TokenService {
	return &tokenServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      conf,
	}
}

// Audit verifies an existing token in respect to its privileges for a specified resource.  It starts by validating
// the status of the token passed in the request, and if that token is currently valid and contains the specified
// resource, returns the same token.  If the token is invalid or outdated, or doesn't contain the specified resource,
// then a new token is generated and returned.
// Returns nil if no new token has been issued, otherwise returns the new token string
func (s *tokenServiceImpl) Audit(ctx context.Context, identity *account.Identity, tokenString string, resourceID string) (*string, error) {
	// Confirm that the resource exists
	err := s.Repositories().ResourceRepository().CheckExists(ctx, resourceID)
	if err != nil {
		switch err.(type) {
		case errors.NotFoundError:
			return nil, errors.NewBadParameterErrorFromString("resourceID", resourceID, "resource does not exist")
		}
		return nil, err
	}

	// Get the token manager from the context
	manager, err := token.ReadManagerFromContext(ctx)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	// Now parse the token string that was passed in
	tokenClaims, err := manager.ParseToken(ctx, tokenString)
	if err != nil {
		return nil, errors.NewBadParameterErrorFromString("tokenString", tokenString, "invalid token string could not be parsed")
	}

	// Now that we have the identity and have parsed the token, we can see if we have a record of the token in the database
	var tokenID uuid.UUID

	// Extract the kid from the token
	tokenID, err = uuid.FromString(tokenClaims.Id)
	if err != nil {
		return nil, errors.NewBadParameterErrorFromString("jti", tokenClaims.Id, "invalid jti identifier - not a UUID")
	}

	loadedToken, err := s.Repositories().TokenRepository().Load(ctx, tokenID)
	if err != nil {
		// This is not an error per se, so we'll just log an informational message
		log.Info(ctx, map[string]interface{}{
			"token_id": tokenID,
		}, "token with specified id not found")
	}

	// Check whether the resource exists in the token already (only for valid RPT tokens)
	resourceExistsInToken := false
	if loadedToken != nil && tokenClaims.Permissions != nil {
		for _, tokenPermission := range *tokenClaims.Permissions {
			if *tokenPermission.ResourceSetID == resourceID {
				resourceExistsInToken = true
			}
		}
	}

	if loadedToken != nil {
		// Confirm that the token belongs to the current identity
		if loadedToken.IdentityID != identity.ID {
			return nil, errors.NewUnauthorizedError("invalid token for identity")
		}

		// If the token exists and its status is valid, return an empty string
		if loadedToken.Valid() && resourceExistsInToken {
			return nil, nil
		}

		// We now process the various token status codes in order of priority, starting with DEPROVISIONED
		if loadedToken.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED) {
			return nil, errors.NewUnauthorizedErrorWithCode("token deprovisioned", errors.UNAUTHORIZED_CODE_TOKEN_DEPROVISIONED)
		}

		// If the token has been revoked or the user is logged out, we respond in the same way
		if loadedToken.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED) || loadedToken.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT) {
			return nil, errors.NewUnauthorizedErrorWithCode("token revoked or logged out", errors.UNAUTHORIZED_CODE_TOKEN_REVOKED)
		}

		// If the token is stale, yet the resource exists in the token
		// we can re-evaluate its privileges to determine whether they have changed.
		// If the privileges are unchanged, then reset the token status
		if loadedToken.HasStatus(tokenPkg.TOKEN_STATUS_STALE) && resourceExistsInToken {
			// Query for all of the token's privileges
			privileges, err := s.Repositories().TokenRepository().ListPrivileges(ctx, tokenID)
			if err != nil {
				return nil, errors.NewInternalError(ctx, err)
			}

			scopesChanged := false
			permissionsChanged := false

			// If the number of permissions in the token is different to what is stored in the database, then
			// something has definitely changed
			if len(privileges) != len(*tokenClaims.Permissions) {
				permissionsChanged = true
			} else {
				// Compare the scopes to those contained in the current token
				for _, tokenPermission := range *tokenClaims.Permissions {
					// Retrieve the up to date scopes for the resource
					privilegeCache, err := s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, *tokenPermission.ResourceSetID)
					if err != nil {
						return nil, errors.NewInternalError(ctx, err)
					}

					// Compare the scopes of the resource with the scopes in the token
					scopes := privilegeCache.ScopesAsArray()
					if !s.scopesEquivalent(tokenPermission.Scopes, scopes) {
						scopesChanged = true
						break
					}

					resourceFound := false

					// Also confirm that the resources in the token's permissions match those stored in the database
					for _, priv := range privileges {
						if priv.ResourceID == *tokenPermission.ResourceSetID {
							resourceFound = true
						}
					}

					if !resourceFound {
						permissionsChanged = true
						break
					}
				}
			}

			// If the scopes haven't changed, and the permission set is the same, and the specified resouce ID is
			// already contained in the current token, then reset the token status to valid and return an empty string
			if !scopesChanged && !permissionsChanged {
				loadedToken.Status = 0
				err = s.Repositories().TokenRepository().Save(ctx, loadedToken)
				if err != nil {
					return nil, errors.NewInternalError(ctx, err)
				}

				return nil, nil
			}
		}
	}

	// If we've gotten this far, it means that either no existing token was found, or the token that was found
	// has been marked with status STALE and its privileges have changed, in either case we must generate a new token
	signedToken := ""

	err = s.ExecuteInTransaction(func() error {

		// Initialize an array of permission objects that will be included in the token
		perms := []token.Permissions{}

		// Initialize an array of TokenPrivilege objects so that we can persist a record of the token's privileges to the database
		tokenPrivs := []tokenRepo.TokenPrivilege{}

		// Populate the scopes for the requested resource
		privilegeCache, err := s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, resourceID)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		perm := &token.Permissions{
			ResourceSetID: &resourceID,
			Scopes:        privilegeCache.ScopesAsArray(),
			Expiry:        privilegeCache.ExpiryTime.Unix(),
		}

		perms = append(perms, *perm)

		tokenPriv := &tokenRepo.TokenPrivilege{
			PrivilegeCacheID: privilegeCache.PrivilegeCacheID,
		}

		tokenPrivs = append(tokenPrivs, *tokenPriv)

		// If an existing RPT token is being replaced with a new token, then populate it with the privileges from the
		// existing token.  HOWEVER, don't exceed the maximum configured permissions for the token
		if loadedToken != nil {
			oldTokenPrivs, err := s.Repositories().TokenRepository().ListPrivileges(ctx, loadedToken.TokenID)
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}

			// Sort the old token privileges by expiry time, from latest to earliest
			sort.Slice(oldTokenPrivs, func(i, j int) bool {
				return oldTokenPrivs[i].ExpiryTime.After(oldTokenPrivs[j].ExpiryTime)
			})

			// Loop through the privileges stored in the previous token, and add them to the permissions of the
			// new token, breaking once the maximum permission limit has been hit
			for _, oldPriv := range oldTokenPrivs {
				// If we have hit the maximum permissions limit then break
				if len(perms) >= s.config.GetRPTTokenMaxPermissions() {
					break
				}

				// Don't process the same resource that was already specified for this request
				if oldPriv.ResourceID == resourceID {
					continue
				}

				// Retrieve the cached privileges for the resource
				privilegeCache, err := s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, oldPriv.ResourceID)
				if err != nil {
					return errors.NewInternalError(ctx, err)
				}

				oldPrivResourceID := oldPriv.ResourceID

				// Create a new permissions object for the RPT token and store it in the array
				perm := &token.Permissions{
					ResourceSetID: &oldPrivResourceID,
					Scopes:        privilegeCache.ScopesAsArray(),
					Expiry:        privilegeCache.ExpiryTime.Unix(),
				}

				perms = append(perms, *perm)

				// Create a token privilege object to store in the database
				tokenPriv := &tokenRepo.TokenPrivilege{
					PrivilegeCacheID: privilegeCache.PrivilegeCacheID,
				}

				tokenPrivs = append(tokenPrivs, *tokenPriv)
			}
		}

		// Generate a new RPT token
		generatedToken, err := manager.GenerateUnsignedRPTTokenForIdentity(ctx, tokenClaims, *identity, &perms)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Extract the new jti claim (the Token ID) from the token, and the expiry time, in order to create a database record for it
		claims := generatedToken.Claims.(jwt.MapClaims)
		id := claims["jti"].(string)
		expiresAt := claims["exp"].(int64)

		// Convert the new Token ID to a UUID value
		newTokenID, err := uuid.FromString(id)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Create a new Token record in the database
		newTokenRecord := &tokenRepo.Token{
			TokenID:    newTokenID,
			IdentityID: identity.ID,
			Status:     0,
			TokenType:  tokenPkg.TOKEN_TYPE_RPT,
			ExpiryTime: time.Unix(expiresAt, 0),
		}

		// Persist the token record to the database
		err = s.Repositories().TokenRepository().Create(ctx, newTokenRecord)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Assign privileges to the token record, and persist them to the database
		for _, tokenPriv := range tokenPrivs {
			tokenPriv.TokenID = newTokenRecord.TokenID
			err = s.Repositories().TokenRepository().CreatePrivilege(ctx, &tokenPriv)
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}
		}

		// Sign the token
		signedToken, err = manager.SignRPTToken(ctx, generatedToken)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &signedToken, nil
}

func (s *tokenServiceImpl) scopesEquivalent(value1 []string, value2 []string) bool {
	if len(value1) != len(value2) {
		return false
	}

	for _, val1 := range value1 {
		found := false
		for _, val2 := range value2 {
			if val1 == val2 {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}
