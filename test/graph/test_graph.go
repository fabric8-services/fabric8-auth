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
	g.graphObjects[id] = wrapper
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
	require.NotNil(g.t, teamID, "Must specified a uuid parameter for the team ID")
	w := loadTeamWrapper(g, *teamID)
	g.register(g.generateIdentifier(params), &w)
	return &w
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
	require.NotNil(g.t, identityID, "Must specified a uuid parameter for the identity ID")
	w := loadIdentityWrapper(g, *identityID)
	g.register(g.generateIdentifier(params), &w)
	return &w
}
