package graph

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/satori/go.uuid"
	"testing"
)

// TestGraph manages an object graph of domain objects for the purposes of testing
type TestGraph struct {
	t            *testing.T
	app          application.Application
	ctx          context.Context
	graphObjects map[string]interface{}
}

// baseWrapper is the base struct for other Wrapper structs
type baseWrapper struct {
	graph *TestGraph
}

// Identifier is used to explicitly set the unique identifier for a graph object
type Identifier struct {
	value string
}

// NewTestGraph creates a new test graph
func NewTestGraph(t *testing.T, app application.Application, ctx context.Context) TestGraph {
	return TestGraph{t: t, app: app, ctx: ctx, graphObjects: make(map[string]interface{})}
}

// register registers a new wrapper object with the test graph's internal list of objects
func (g *TestGraph) register(id string, wrapper interface{}) {
	g.graphObjects[id] = wrapper
}

func (g *TestGraph) generateIdentifier(params []interface{}) string {
	for i, _ := range params {
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

func (g *TestGraph) GetUser(id string) *userWrapper {
	return g.graphObjects[id].(*userWrapper)
}

// CreateSpace creates a new space wrapper object
func (g *TestGraph) CreateSpace(params ...interface{}) *spaceWrapper {
	obj := newSpaceWrapper(g, params)
	g.register(g.generateIdentifier(params), &obj)
	return &obj
}

func (g *TestGraph) GetSpace(id string) *spaceWrapper {
	return g.graphObjects[id].(*spaceWrapper)
}
