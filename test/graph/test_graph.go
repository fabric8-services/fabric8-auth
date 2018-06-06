package graph

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

// TestGraph manages an object graph of domain objects for the purposes of testing
type TestGraph struct {
	t            *testing.T
	app          application.Application
	ctx          context.Context
	graphObjects map[string]interface{}
	db           *gorm.DB
}

// baseWrapper is the base struct for other Wrapper structs
type baseWrapper struct {
	graph *TestGraph
}

func (w *baseWrapper) identityIDFromWrapper(wrapper interface{}) uuid.UUID {
	switch t := wrapper.(type) {
	case *userWrapper:
		return t.identity.ID
	case *identityWrapper:
		return t.identity.ID
	}
	require.True(w.graph.t, false, "wrapper must be either user wrapper or identity wrapper")
	return uuid.UUID{}
}

// Identifier is used to explicitly set the unique identifier for a graph object
type Identifier struct {
	value string
}

// NewTestGraph creates a new test graph
func NewTestGraph(t *testing.T, app application.Application, ctx context.Context, db *gorm.DB) TestGraph {
	return TestGraph{t: t, app: app, ctx: ctx, graphObjects: make(map[string]interface{}), db: db}
}

// register registers a new wrapper object with the test graph's internal list of objects
func (g *TestGraph) register(id string, wrapper interface{}) {
	if _, found := g.graphObjects[id]; found {
		require.True(g.t, false, "object identifier '%s' already registered", id)
	} else {
		g.graphObjects[id] = wrapper
	}
}

func (g *TestGraph) generateIdentifier(params []interface{}) string {
	for i := range params {
		switch t := params[i].(type) {
		case Identifier:
			return t.value
		}
	}
	return uuid.NewV4().String()
}

func (g *TestGraph) ID(value string) Identifier {
	return Identifier{value}
}

// CreateUser creates a new user wrapper object
func (g *TestGraph) CreateUser(params ...interface{}) *userWrapper {
	obj := newUserWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) UserByID(id string) *userWrapper {
	return g.graphObjects[id].(*userWrapper)
}

// CreateSpace creates a new space wrapper object
func (g *TestGraph) CreateSpace(params ...interface{}) *spaceWrapper {
	obj := newSpaceWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) SpaceByID(id string) *spaceWrapper {
	return g.graphObjects[id].(*spaceWrapper)
}

func (g *TestGraph) CreateResourceType(params ...interface{}) *resourceTypeWrapper {
	obj := newResourceTypeWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) ResourceTypeByID(id string) *resourceTypeWrapper {
	return g.graphObjects[id].(*resourceTypeWrapper)
}

func (g *TestGraph) LoadResourceType(params ...interface{}) *resourceTypeWrapper {
	var resourceTypeID *uuid.UUID
	var resourceTypeName *string
	for i := range params {
		switch t := params[i].(type) {
		case *uuid.UUID:
			resourceTypeID = t
		case uuid.UUID:
			resourceTypeID = &t
		case string:
			resourceTypeName = &t
		case *string:
			resourceTypeName = t
		}
	}

	require.True(g.t, resourceTypeID != nil || resourceTypeName != nil, "must specify either resource_type_id or name parameter for the resource type to load")

	w := loadResourceTypeWrapper(g, resourceTypeID, resourceTypeName)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) CreateResource(params ...interface{}) *resourceWrapper {
	obj := newResourceWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) ResourceByID(id string) *resourceWrapper {
	return g.graphObjects[id].(*resourceWrapper)
}

func (g *TestGraph) CreateTeam(params ...interface{}) *teamWrapper {
	obj := newTeamWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) TeamByID(id string) *teamWrapper {
	return g.graphObjects[id].(*teamWrapper)
}

func (g *TestGraph) LoadTeam(params ...interface{}) *teamWrapper {
	var teamID *uuid.UUID
	for i := range params {
		switch t := params[i].(type) {
		case *uuid.UUID:
			teamID = t
		}
	}
	require.NotNil(g.t, teamID, "Must specify a uuid parameter for the team ID")
	w := loadTeamWrapper(g, *teamID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) CreateOrganization(params ...interface{}) *organizationWrapper {
	obj := newOrganizationWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) LoadOrganization(params ...interface{}) *organizationWrapper {
	var organizationID *uuid.UUID
	for i := range params {
		switch t := params[i].(type) {
		case *uuid.UUID:
			organizationID = t
		}
	}
	require.NotNil(g.t, organizationID, "Must specify a uuid parameter for the organization ID")
	w := loadOrganizationWrapper(g, *organizationID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) OrganizationByID(id string) *organizationWrapper {
	return g.graphObjects[id].(*organizationWrapper)
}

func (g *TestGraph) CreateIdentity(params ...interface{}) *identityWrapper {
	obj := newIdentityWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) IdentityByID(id string) *identityWrapper {
	return g.graphObjects[id].(*identityWrapper)
}

func (g *TestGraph) LoadIdentity(params ...interface{}) *identityWrapper {
	var identityID *uuid.UUID
	for i := range params {
		switch t := params[i].(type) {
		case *uuid.UUID:
			identityID = t
		case uuid.UUID:
			identityID = &t
		}
	}
	require.NotNil(g.t, identityID, "Must specify a uuid parameter for the identity ID")
	w := loadIdentityWrapper(g, *identityID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) LoadResource(params ...interface{}) *resourceWrapper {
	var resourceID *string
	for i := range params {
		switch t := params[i].(type) {
		case *string:
			resourceID = t
		case string:
			resourceID = &t
		}
	}
	require.NotNil(g.t, resourceID, "Must specify a string parameter for the resource ID")
	w := loadResourceWrapper(g, *resourceID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) LoadSpace(params ...interface{}) *spaceWrapper {
	var resourceID *string
	for i := range params {
		switch t := params[i].(type) {
		case *string:
			resourceID = t
		case string:
			resourceID = &t
		case *uuid.UUID:
			id := t.String()
			resourceID = &id
		case uuid.UUID:
			id := t.String()
			resourceID = &id
		}
	}
	require.NotNil(g.t, resourceID, "Must specify a string parameter for the space ID")
	w := loadSpaceWrapper(g, *resourceID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}

func (g *TestGraph) CreateRole(params ...interface{}) *roleWrapper {
	obj := newRoleWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) RoleByID(id string) *roleWrapper {
	return g.graphObjects[id].(*roleWrapper)
}

func (g *TestGraph) CreateDefaultRoleMapping(params ...interface{}) *defaultRoleMappingWrapper {
	obj := newDefaultRoleMappingWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) DefaultRoleMappingByID(id string) *defaultRoleMappingWrapper {
	return g.graphObjects[id].(*defaultRoleMappingWrapper)
}

func (g *TestGraph) CreateRoleMapping(params ...interface{}) *roleMappingWrapper {
	obj := newRoleMappingWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) RoleMappingByID(id string) *roleMappingWrapper {
	return g.graphObjects[id].(*roleMappingWrapper)
}
