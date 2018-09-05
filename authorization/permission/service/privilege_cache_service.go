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
	"time"
)

// PrivilegeCacheServiceConfiguration represents the configuration options for the privilege cache service
type PrivilegeCacheServiceConfiguration interface {
	GetPrivilegeCacheExpirySeconds() int64
}

// privilegeCacheServiceImpl is the implementation of the interface for PrivilegeCacheService
type privilegeCacheServiceImpl struct {
	base.BaseService
	conf PrivilegeCacheServiceConfiguration
}

// NewPrivilegeCacheService creates a new service.
func NewPrivilegeCacheService(context servicecontext.ServiceContext, config PrivilegeCacheServiceConfiguration) service.PrivilegeCacheService {
	return &privilegeCacheServiceImpl{
		BaseService: base.NewBaseService(context),
		conf:        config,
	}
}

// CachedPrivileges returns the cached privileges that an identity has for a specified resource.
// If there are no privileges cached, or the cached value is stale, the privileges will be re-calculated and
// the cached value updated.
func (s *privilegeCacheServiceImpl) CachedPrivileges(ctx context.Context, identityID uuid.UUID, resourceID string) (*permission.PrivilegeCache, error) {
	nowTime := time.Now()

	// Attempt to load the privilege cache record from the database
	privilegeCache, err := s.Repositories().PrivilegeCacheRepository().FindForIdentityResource(ctx, identityID, resourceID)
	notFound := false
	if err != nil {
		switch err.(type) {
		case errors.NotFoundError:
			notFound = true
		}
	}

	// If there was no privilege cache record found, or the record has expired, then recalculate the scopes and either
	// update the existing record, or create a new one
	if notFound || privilegeCache.Stale || privilegeCache.ExpiryTime.Before(nowTime) {
		scopes, err := s.Repositories().IdentityRoleRepository().FindScopesByIdentityAndResource(ctx, identityID, resourceID)
		if err != nil {
			return nil, errors.NewInternalError(ctx, err)
		}

		scopeList := strings.Join(scopes, ",")

		// If the privilege cache record doesn't exist, create a new one
		if notFound {
			privilegeCache = &permission.PrivilegeCache{
				IdentityID: identityID,
				ResourceID: resourceID,
				Scopes:     scopeList,
				Stale:      false,
				ExpiryTime: time.Now().Local().Add(time.Second * time.Duration(s.conf.GetPrivilegeCacheExpirySeconds())),
			}

			err = s.Repositories().PrivilegeCacheRepository().Create(ctx, privilegeCache)
			if err != nil {
				return nil, errors.NewInternalError(ctx, err)
			}
		} else {
			// Otherwise update the existing record
			privilegeCache.Scopes = scopeList
			privilegeCache.Stale = false
			privilegeCache.ExpiryTime = time.Now().Local().Add(time.Second * time.Duration(s.conf.GetPrivilegeCacheExpirySeconds()))

			err = s.Repositories().PrivilegeCacheRepository().Save(ctx, privilegeCache)
			if err != nil {
				return nil, errors.NewInternalError(ctx, err)
			}
		}
	}

	return privilegeCache, nil
}

func (s *privilegeCacheServiceImpl) NotifyIdentityResourcePrivilegesUpdated(ctx context.Context, identityID uuid.UUID, resourceID string) error {
	return s.Repositories().PrivilegeCacheRepository().FlagAsStale(ctx, identityID, resourceID)
}

func (s *privilegeCacheServiceImpl) NotifyMembershipChanged(ctx context.Context, memberID uuid.UUID, memberOf uuid.UUID) error {
	// TODO implement this
	return nil
}
