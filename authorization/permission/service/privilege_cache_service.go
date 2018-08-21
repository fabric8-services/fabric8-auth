package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/satori/go.uuid"
	"strings"
)

// privilegeCacheServiceImpl is the implementation of the interface for PrivilegeCacheService
type privilegeCacheServiceImpl struct {
	base.BaseService
}

// NewPrivilegeCacheService creates a new service.
func NewPrivilegeCacheService(context servicecontext.ServiceContext) service.PrivilegeCacheService {
	return &privilegeCacheServiceImpl{base.NewBaseService(context)}
}

func (s *privilegeCacheServiceImpl) ScopesForResource(ctx context.Context, identityID uuid.UUID, resourceID string) ([]string, error) {
	privilegeCache, err := s.Repositories().PrivilegeCacheRepository().FindForIdentityResource(ctx, identityID, resourceID)
	notFound := false
	if err != nil {
		switch err.(type) {
		case errors.NotFoundError:
			notFound = true
		}
	}

	if notFound || privilegeCache.Stale || s.privilegeCacheExpired(privilegeCache) {
		scopes, err := s.Repositories().IdentityRoleRepository().FindScopesByIdentityAndResource(ctx, identityID, resourceID)
		if err != nil {
			return nil, errors.NewInternalError(ctx, err)
		}

		scopeList := strings.Join(scopes, ",")

		if notFound {
			privilegeCache = &permission.PrivilegeCache{
				IdentityID: identityID,
				ResourceID: resourceID,
				Scopes:     scopeList,
				Stale:      false,
				//ExpiryTime: ??,
			}

			err = s.Repositories().PrivilegeCacheRepository().Create(ctx, privilegeCache)
			if err != nil {
				return nil, errors.NewInternalError(ctx, err)
			}
		} else {
			privilegeCache.Scopes = scopeList
			privilegeCache.Stale = false
			//privilegeCache.ExpiryTime = ??

			err = s.Repositories().PrivilegeCacheRepository().Save(ctx, privilegeCache)
			if err != nil {
				return nil, errors.NewInternalError(ctx, err)
			}
		}

		return scopes, nil
	} else {
		return strings.Split(privilegeCache.Scopes, ","), nil
	}
}

func (s *privilegeCacheServiceImpl) privilegeCacheExpired(privilegeCache *permission.PrivilegeCache) bool {
	// TODO implement this
	return false
}
