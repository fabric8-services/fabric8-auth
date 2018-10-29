package service

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	accountrepo "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	authtoken "github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	tokenrepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"

	"sort"
	"time"
)

// TokenServiceConfiguration the required configuration for the token service implementation
type TokenServiceConfiguration interface {
	manager.TokenManagerConfiguration
	GetRPTTokenMaxPermissions() int
}

type tokenServiceImpl struct {
	base.BaseService
	config       TokenServiceConfiguration
	tokenManager manager.TokenManager
}

// NewTokenService returns a new Token Service
func NewTokenService(context *servicecontext.ServiceContext, config TokenServiceConfiguration) service.TokenService {
	tokenManager, err := manager.NewTokenManager(config)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to create token manager")
	}

	return &tokenServiceImpl{
		BaseService:  base.NewBaseService(context),
		config:       config,
		tokenManager: tokenManager,
	}
}

// Audit verifies an existing token in respect to its privileges for a specified resource.  It starts by validating
// the status of the token passed in the request, and if that token is currently valid and contains the specified
// resource, returns the same token.  If the token is invalid or outdated, or doesn't contain the specified resource,
// then a new token is generated and returned.
// Returns nil if no new token has been issued, otherwise returns the new token string
func (s *tokenServiceImpl) Audit(ctx context.Context, identity *accountrepo.Identity, tokenString string, resourceID string) (*string, error) {
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
	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	// Now parse the token string that was passed in
	tokenClaims, err := tokenManager.ParseToken(ctx, tokenString)
	if err != nil {
		log.Error(ctx, map[string]interface{}{"error": err}, "invalid token string could not be parsed")
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
		if loadedToken.HasStatus(authtoken.TOKEN_STATUS_DEPROVISIONED) {
			return nil, errors.NewUnauthorizedErrorWithCode("token deprovisioned", errors.UNAUTHORIZED_CODE_TOKEN_DEPROVISIONED)
		}

		// If the token has been revoked or the user is logged out, we respond in the same way
		if loadedToken.HasStatus(authtoken.TOKEN_STATUS_REVOKED) || loadedToken.HasStatus(authtoken.TOKEN_STATUS_LOGGED_OUT) {
			return nil, errors.NewUnauthorizedErrorWithCode("token revoked or logged out", errors.UNAUTHORIZED_CODE_TOKEN_REVOKED)
		}

		// If the token is stale, yet the resource exists in the token
		// we can re-evaluate its privileges to determine whether they have changed.
		// If the privileges are unchanged, then reset the token status
		if loadedToken.HasStatus(authtoken.TOKEN_STATUS_STALE) && resourceExistsInToken {
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
		perms := []manager.Permissions{}

		// Initialize an array of TokenPrivilege objects so that we can persist a record of the token's privileges to the database
		tokenPrivs := []tokenrepo.TokenPrivilege{}

		// Populate the scopes for the requested resource
		privilegeCache, err := s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, resourceID)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		perm := &manager.Permissions{
			ResourceSetID: &resourceID,
			Scopes:        privilegeCache.ScopesAsArray(),
			Expiry:        privilegeCache.ExpiryTime.Unix(),
		}

		perms = append(perms, *perm)

		tokenPriv := &tokenrepo.TokenPrivilege{
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

				oldPrivResourceID := oldPriv.ResourceID

				// If the old privilege is stale, then refresh its scopes and expiry time
				if oldPriv.Stale {
					// Lookup the scopes for the old privilege, as they may have changed
					privilegeCache, err = s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, oldPrivResourceID)
					if err != nil {
						return err
					}
					// Create a new permissions object for the RPT token and store it in the array
					perms = append(perms, manager.Permissions{
						ResourceSetID: &oldPrivResourceID,
						Scopes:        privilegeCache.ScopesAsArray(),
						Expiry:        privilegeCache.ExpiryTime.Unix(),
					})
				} else {
					perms = append(perms, manager.Permissions{
						ResourceSetID: &oldPrivResourceID,
						Scopes:        oldPriv.ScopesAsArray(),
						Expiry:        oldPriv.ExpiryTime.Unix(),
					})
				}

				// Create a token privilege object to store in the database
				tokenPriv := &tokenrepo.TokenPrivilege{
					PrivilegeCacheID: oldPriv.PrivilegeCacheID,
				}

				tokenPrivs = append(tokenPrivs, *tokenPriv)
			}
		}

		// Generate a new RPT token
		generatedToken, err := tokenManager.GenerateUnsignedRPTTokenForIdentity(ctx, tokenClaims, *identity, &perms)
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
		newTokenRecord := &tokenrepo.Token{
			TokenID:    newTokenID,
			IdentityID: identity.ID,
			Status:     0,
			TokenType:  authtoken.TOKEN_TYPE_RPT,
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
		signedToken, err = tokenManager.SignRPTToken(ctx, generatedToken)
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

// ExchangeRefreshToken exchanges refreshToken for OauthToken
// TODO investigate merging this with the Refresh() method
func (s *tokenServiceImpl) ExchangeRefreshToken(ctx context.Context, accessToken, refreshToken string) (*manager.TokenSet, error) {

	// Load identity for the refresh token
	var identity *accountrepo.Identity
	claims, err := s.tokenManager.ParseTokenWithMapClaims(ctx, refreshToken)
	if err != nil {
		return nil, errors.NewUnauthorizedError(err.Error())
	}
	sub := claims["sub"]
	if sub == nil {
		return nil, errors.NewUnauthorizedError("missing 'sub' claim in the refresh token")
	}
	identityID, err := uuid.FromString(fmt.Sprintf("%s", sub))
	if err != nil {
		return nil, errors.NewUnauthorizedError(err.Error())
	}

	err = s.ExecuteInTransaction(func() error {
		identity, err = s.Repositories().Identities().LoadWithUser(ctx, identityID)
		return err
	})

	if err != nil {
		// That's OK if we didn't find the identity if the token was issued for an API client
		// Just log it and proceed.
		log.Warn(ctx, map[string]interface{}{
			"err": err,
		}, "failed to load identity when refreshing token; it's OK if the token was issued for an API client")
	}

	if identity != nil && identity.User.Deprovisioned {
		log.Warn(ctx, map[string]interface{}{
			"identity_id": identity.ID,
			"user_name":   identity.Username,
		}, "deprovisioned user tried to refresh token")
		return nil, errors.NewUnauthorizedError("unauthorized access")
	}

	generatedToken, err := s.tokenManager.GenerateUserTokenUsingRefreshToken(ctx, refreshToken, identity)
	if err != nil {
		return nil, err
	}
	// if an RPT token is provided, then use it to obtain a new token with updated permission claims
	if identity != nil && accessToken != "" {
		// TODO: can't we just call s.Refresh(...) now?
		refreshedAccessToken, err := s.Services().TokenService().Refresh(ctx, identity, accessToken)
		if err != nil {
			return nil, err
		}
		log.Debug(ctx, map[string]interface{}{"identity_id": identityID.String()}, "obtained a new access token")
		generatedToken.AccessToken = refreshedAccessToken
	}
	return s.tokenManager.ConvertToken(*generatedToken)
}

// Refresh checks the resource permissions in the given tokenString for the given user, and returns a
// new RPT Token (with a new expiry time and updated permissions if needed)
func (s *tokenServiceImpl) Refresh(ctx context.Context, identity *accountrepo.Identity, accessToken string) (string, error) {
	log.Debug(ctx, map[string]interface{}{"identity_id": identity.ID.String()}, "refreshing a user token...")
	// Get the token manager from the context
	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	if err != nil {
		return "", errors.NewInternalError(ctx, err)
	}
	// Now parse the token string that was passed in
	accessTokenClaims, err := tokenManager.ParseToken(ctx, accessToken)
	if err != nil {
		return "", errors.NewUnauthorizedError("failed to parse the request's access token")
	}
	// Now that we have the identity and have parsed the token, we can see if we have a record of the token in the database
	var tokenID uuid.UUID
	// Extract the jti from the token
	tokenID, err = uuid.FromString(accessTokenClaims.Id)
	if err != nil {
		return "", errors.NewBadParameterErrorFromString("jti", accessTokenClaims.Id, "invalid jti identifier - not a UUID")
	}
	loadedToken, err := s.Repositories().TokenRepository().Load(ctx, tokenID)
	if err != nil {
		// This is not an error per se, so we'll just log an informational message
		log.Info(ctx, map[string]interface{}{
			"token_id": tokenID,
		}, "token with specified id not found")
	}
	// check if the token is still valid
	if loadedToken != nil {
		// Confirm that the token belongs to the current identity
		if loadedToken.IdentityID != identity.ID {
			return "", errors.NewUnauthorizedError("invalid token for identity")
		}
		// We now process the various token status codes in order of priority, starting with DEPROVISIONED
		if loadedToken.HasStatus(authtoken.TOKEN_STATUS_DEPROVISIONED) {
			return "", errors.NewUnauthorizedErrorWithCode("token deprovisioned", errors.UNAUTHORIZED_CODE_TOKEN_DEPROVISIONED)
		}
		// If the token has been revoked or the user is logged out, we respond in the same way
		if loadedToken.HasStatus(authtoken.TOKEN_STATUS_REVOKED) || loadedToken.HasStatus(authtoken.TOKEN_STATUS_LOGGED_OUT) {
			return "", errors.NewUnauthorizedErrorWithCode("token revoked or logged out", errors.UNAUTHORIZED_CODE_TOKEN_REVOKED)
		}
	}
	// If we've gotten this far, it means that either no existing token was found, or the token that was found
	// has been marked with status STALE and its privileges have changed, in either case we must generate a new token
	signedToken := ""
	err = s.ExecuteInTransaction(func() error {
		// Initialize an array of permission objects that will be included in the token
		perms := []manager.Permissions{}
		// Initialize an array of TokenPrivilege objects so that we can persist a record of the token's privileges to the database
		tokenPrivs := []tokenrepo.TokenPrivilege{}
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
				oldPrivResourceID := oldPriv.ResourceID
				if loadedToken.Status&authtoken.TOKEN_STATUS_STALE > 0 || oldPriv.Stale {
					privilegeCache, err := s.Services().PrivilegeCacheService().CachedPrivileges(ctx, identity.ID, oldPrivResourceID)
					if err != nil {
						return errors.NewInternalError(ctx, err)
					}
					log.Debug(ctx, map[string]interface{}{"resource_id": oldPrivResourceID, "new_scopes": privilegeCache.ScopesAsArray(), "old_scopes": oldPriv.ScopesAsArray()}, "old privileges are stale")
					perm := &manager.Permissions{
						ResourceSetID: &oldPrivResourceID,
						Scopes:        privilegeCache.ScopesAsArray(),
						Expiry:        privilegeCache.ExpiryTime.Unix(),
					}
					perms = append(perms, *perm)
				} else {
					// Create a new permissions object for the RPT token and store it in the array
					perm := &manager.Permissions{
						ResourceSetID: &oldPrivResourceID,
						Scopes:        oldPriv.ScopesAsArray(),
						Expiry:        oldPriv.ExpiryTime.Unix(),
					}
					perms = append(perms, *perm)
				}
				// Create a token privilege object to store in the database
				tokenPriv := &tokenrepo.TokenPrivilege{
					PrivilegeCacheID: oldPriv.PrivilegeCacheID,
				}
				tokenPrivs = append(tokenPrivs, *tokenPriv)
			}
		}
		// update the expiry
		now := time.Now().Unix()
		accessTokenClaims.ExpiresAt = time.Unix(now+s.config.GetAccessTokenExpiresIn(), 0).Unix()
		// Generate a new RPT token
		generatedToken, err := tokenManager.GenerateUnsignedRPTTokenForIdentity(ctx, accessTokenClaims, *identity, &perms)
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
		newTokenRecord := &tokenrepo.Token{
			TokenID:    newTokenID,
			IdentityID: identity.ID,
			Status:     0,
			TokenType:  authtoken.TOKEN_TYPE_RPT,
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
		signedToken, err = tokenManager.SignRPTToken(ctx, generatedToken)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// TODO remove the goa.RequestData param from here
// RetrieveToken
func (c *tokenServiceImpl) RetrieveToken(ctx context.Context, forResource string, req *goa.RequestData, forcePull *bool) (*app.ExternalToken, *string, error) {
	if forResource == "" {
		return nil, nil, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL")
	}

	var currentIdentityID uuid.UUID
	serviceAccount := authtoken.IsSpecificServiceAccount(ctx, authtoken.OsoProxy, authtoken.Tenant, authtoken.JenkinsIdler, authtoken.JenkinsProxy)
	if serviceAccount {
		// Extract SA ID
		id, err := manager.ContextIdentity(ctx)
		if err != nil {
			return nil, nil, err
		}
		currentIdentityID = *id
	} else {
		// Extract user ID
		currentIdentity, err := c.Services().UserService().LoadContextIdentityIfNotDeprovisioned(ctx)
		if err != nil {
			return nil, nil, err
		}
		currentIdentityID = currentIdentity.ID
	}

	var appResponse app.ExternalToken

	linkingProvider, err := c.Factories().LinkingProviderFactory().NewLinkingProvider(ctx, currentIdentityID,
		rest.AbsoluteURL(req, "", nil), forResource)
	if err != nil {
		return nil, nil, err
	}

	osProvider, ok := linkingProvider.(provider.OpenShiftIdentityProvider)
	if ok && serviceAccount {
		// This is a request from OSO proxy, tenant, Jenkins Idler, or Jenkins proxy service to obtain a cluster wide token
		return c.retrieveClusterToken(ctx, forResource, forcePull, osProvider)
	}

	externalToken, err := c.loadToken(ctx, linkingProvider, currentIdentityID)
	if err != nil {
		return nil, nil, err
	}
	if externalToken != nil {
		updatedToken, errorResponse, err := c.updateProfileIfEmpty(ctx, forResource, req, linkingProvider, externalToken, forcePull)
		if err != nil {
			return nil, errorResponse, err
		}

		appResponse = app.ExternalToken{
			Scope:          updatedToken.Scope,
			AccessToken:    updatedToken.Token,
			TokenType:      "bearer", // We aren't saving the token_type in the database
			Username:       updatedToken.Username,
			ProviderAPIURL: linkingProvider.URL(),
		}

		return &appResponse, nil, nil
	}
	providerName := linkingProvider.TypeName()
	linkURL := rest.AbsoluteURL(req, fmt.Sprintf("%s?for=%s", client.LinkTokenPath(), forResource), nil)
	errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is missing. Link %s account\"", linkURL, providerName, providerName)
	return nil, &errorResponse, errors.NewUnauthorizedError("token is missing")
}

func (c *tokenServiceImpl) DeleteExternalToken(ctx context.Context, currentIdentity uuid.UUID, authURL string, forResource string) error {

	providerConfig, err := c.Factories().LinkingProviderFactory().NewLinkingProvider(ctx, currentIdentity, authURL, forResource)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	// Delete from local DB
	err = c.ExecuteInTransaction(func() error {
		err := c.Repositories().Identities().CheckExists(ctx, currentIdentity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		tokens, err := c.Repositories().ExternalTokens().LoadByProviderIDAndIdentityID(ctx, providerConfig.ID(), currentIdentity)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			for _, token := range tokens {
				err = c.Repositories().ExternalTokens().Delete(ctx, token.ID)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		if val, _ := errors.IsUnauthorizedError(err); val {
			return err
		}
		return errors.NewInternalError(ctx, err)
	}
	return nil
}

// updateProfileIfEmpty checks if the username is missing in the token record (may happen to old accounts)
// loads the user profile from the identity provider and saves the username in the external token
func (c *tokenServiceImpl) updateProfileIfEmpty(ctx context.Context, forResource string, req *goa.RequestData,
	prov provider.LinkingProvider, token *tokenrepo.ExternalToken, forcePull *bool) (tokenrepo.ExternalToken, *string, error) {
	externalToken := *token
	if forcePull != nil && *forcePull {
		userProfile, err := prov.Profile(ctx, oauth2.Token{AccessToken: token.Token})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":           err,
				"for":           forResource,
				"provider_name": prov.TypeName(),
			}, "Unable to fetch user profile for external token. Account relinking may be required.")
			linkURL := rest.AbsoluteURL(req, fmt.Sprintf("%s?for=%s", client.LinkTokenPath(), forResource), nil)
			errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is not valid or expired. Relink %s account\"",
				linkURL, prov.TypeName(), prov.TypeName())
			return externalToken, &errorResponse, errors.NewUnauthorizedError(err.Error())
		}
		externalToken.Username = userProfile.Username
		err = c.ExecuteInTransaction(func() error {
			return c.Repositories().ExternalTokens().Save(ctx, &externalToken)
		})
		return externalToken, nil, err
	}
	return externalToken, nil, nil
}

func (c *tokenServiceImpl) retrieveClusterToken(ctx context.Context, forResource string, forcePull *bool, provider provider.OpenShiftIdentityProvider) (*app.ExternalToken, *string, error) {
	username := provider.OSOCluster().ServiceAccountUsername
	if forcePull != nil && *forcePull {
		userProfile, err := provider.Profile(ctx, oauth2.Token{AccessToken: provider.OSOCluster().ServiceAccountToken})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
				"for": forResource,
			}, "unable to fetch user profile for cluster token")
			errorResponse := fmt.Sprintf("LINK description=\"%s cluster token is not valid or expired", provider.OSOCluster().APIURL)
			return nil, &errorResponse, errors.NewUnauthorizedError(err.Error())
		}
		if provider.OSOCluster().ServiceAccountUsername != userProfile.Username {
			log.Warn(ctx, map[string]interface{}{
				"for": forResource,
				"configuration_username": provider.OSOCluster().ServiceAccountUsername,
				"user_profile_username":  userProfile.Username,
			}, "username from user profile for cluster token does not match username stored in configuration")
			username = userProfile.Username
		}
	}

	clusterToken := app.ExternalToken{
		Scope:          "<unknown>",
		AccessToken:    provider.OSOCluster().ServiceAccountToken,
		TokenType:      "bearer",
		Username:       username,
		ProviderAPIURL: provider.OSOCluster().APIURL,
	}
	log.Info(ctx, map[string]interface{}{
		"cluster": provider.OSOCluster().Name,
	}, "Returning a cluster wide token")
	return &clusterToken, nil, nil
}

func (c *tokenServiceImpl) loadToken(ctx context.Context, prov provider.LinkingProvider, currentIdentity uuid.UUID) (*tokenrepo.ExternalToken, error) {
	var externalToken *tokenrepo.ExternalToken
	err := c.ExecuteInTransaction(func() error {
		err := c.Repositories().Identities().CheckExists(ctx, currentIdentity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		tokens, err := c.Repositories().ExternalTokens().LoadByProviderIDAndIdentityID(ctx, prov.ID(), currentIdentity)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			externalToken = &tokens[0]
		}
		return nil

	})
	return externalToken, err
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
