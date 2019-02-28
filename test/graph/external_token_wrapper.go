package graph

import (
	"reflect"

	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/log"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// externalTokenWrapper represents a Token domain object
type externalTokenWrapper struct {
	baseWrapper
	externalToken *tokenRepo.ExternalToken
}

func newExternalTokenWrapper(g *TestGraph, params []interface{}) interface{} {
	w := externalTokenWrapper{baseWrapper: baseWrapper{g}}
	w.externalToken = &tokenRepo.ExternalToken{}
	var identity *repository.Identity
	var providerID *string
	for _, p := range params {
		log.Debug(nil, map[string]interface{}{"param_type": reflect.TypeOf(p), "param_value": p}, "processing external token constructor param")
		switch p := p.(type) {
		case string:
			providerID = &p
		case *userWrapper:
			identity = p.Identity()
		case userWrapper:
			identity = p.Identity()
		case *identityWrapper:
			identity = p.Identity()
		case identityWrapper:
			identity = p.Identity()
		}
	}
	// allow for on-the-fly creation of identity
	if identity == nil {
		identity = w.graph.CreateUser().Identity()
	}
	// ... but the provider type is required
	require.NotNil(g.t, providerID)
	w.externalToken.IdentityID = identity.ID
	w.externalToken.ProviderID, _ = uuid.FromString(*providerID)
	w.externalToken.Token = uuid.NewV4().String()

	err := g.app.ExternalTokens().Create(g.ctx, w.externalToken)
	require.NoError(g.t, err)

	return &w
}

func (w *externalTokenWrapper) ID() uuid.UUID {
	return w.externalToken.ID
}
