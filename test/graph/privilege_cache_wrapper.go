package graph

import (
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"strings"
)

// privilegeCacheWrapper represents cached user privileges calculated for a resource
type privilegeCacheWrapper struct {
	baseWrapper
	privilegeCache *tokenRepo.PrivilegeCache
}

func newPrivilegeCacheWrapper(g *TestGraph, params []interface{}) interface{} {
	w := privilegeCacheWrapper{baseWrapper: baseWrapper{g}}

	w.privilegeCache = &tokenRepo.PrivilegeCache{}

	var identityID uuid.NullUUID = uuid.NullUUID{}
	var resourceID string
	var scopes []string

	for i := range params {
		switch t := params[i].(type) {
		case *identityWrapper:
			identityID.UUID = t.Identity().ID
		case identityWrapper:
			identityID.UUID = t.Identity().ID
		case *resourceWrapper:
			resourceID = t.ResourceID()
		case resourceWrapper:
			resourceID = t.ResourceID()
		case string:
			scopes = append(scopes, t)
		}
	}

	if identityID.Valid {
		w.privilegeCache.IdentityID = identityID.UUID
	} else {
		w.privilegeCache.IdentityID = w.graph.CreateUser().IdentityID()
	}

	if resourceID != "" {
		w.privilegeCache.ResourceID = resourceID
	} else {
		w.privilegeCache.ResourceID = w.graph.CreateResource().ResourceID()
	}

	w.privilegeCache.Scopes = strings.Join(scopes, ",")

	err := g.app.PrivilegeCacheRepository().Create(g.ctx, w.privilegeCache)
	require.NoError(g.t, err)

	return &w
}

func (w *privilegeCacheWrapper) PrivilegeCache() *tokenRepo.PrivilegeCache {
	return w.privilegeCache
}
