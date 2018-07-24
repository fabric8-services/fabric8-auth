package graph

import (
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"strings"
)

// tokenResourceWrapper represents an RPT Token domain object
type tokenResourceWrapper struct {
	baseWrapper
	tokenResource *tokenRepo.TokenResource
}

func newTokenResourceWrapper(g *TestGraph, params []interface{}) interface{} {
	w := tokenResourceWrapper{baseWrapper: baseWrapper{g}}

	w.tokenResource = &tokenRepo.TokenResource{}

	var tokenID *uuid.UUID
	var resourceID string
	var scopes []string

	for i := range params {
		switch t := params[i].(type) {
		case *tokenWrapper:
			val := t.TokenID()
			tokenID = &val
		case tokenWrapper:
			val := t.TokenID()
			tokenID = &val
		case *resourceWrapper:
			resourceID = t.ResourceID()
		case resourceWrapper:
			resourceID = t.ResourceID()
		case string:
			scopes = append(scopes, t)
		}
	}

	if tokenID != nil {
		w.tokenResource.TokenID = *tokenID
	} else {
		w.tokenResource.TokenID = w.graph.CreateRPTToken().TokenID()
	}

	if resourceID != "" {
		w.tokenResource.ResourceID = resourceID
	} else {
		w.tokenResource.ResourceID = w.graph.CreateResource().ResourceID()
	}

	w.tokenResource.Scopes = strings.Join(scopes, ",")

	err := g.app.TokenResourceRepository().Create(g.ctx, w.tokenResource)
	require.NoError(g.t, err)

	return &w
}

func (w *tokenResourceWrapper) TokenResource() *tokenRepo.TokenResource {
	return w.tokenResource
}
