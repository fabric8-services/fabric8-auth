package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	resourceservice "github.com/fabric8-services/fabric8-auth/authorization/resource/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	resourceService resourceservice.ResourceService
}

func TestRunResourceServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.resourceService = resourceservice.NewResourceService(s.Application, s.Application)
}

func (s *resourceServiceBlackBoxTest) TestRegisterResourceUnknownResourceTypeFails() {
	resourceID := uuid.NewV4().String()
	unknownResourceType := uuid.NewV4().String()
	_, err := s.resourceService.Register(context.Background(), unknownResourceType, &resourceID, nil)
	require.EqualError(s.T(), err, fmt.Sprintf("Bad value for parameter 'type': '%s' - resource_type with name '%s' not found", unknownResourceType, unknownResourceType))
}

func (s *resourceServiceBlackBoxTest) TestRegisterResourceUnknownParentResourceFails() {
	resourceID := uuid.NewV4().String()
	unknownParentID := uuid.NewV4().String()
	_, err := s.resourceService.Register(context.Background(), authorization.ResourceTypeSpace, &resourceID, &unknownParentID)
	require.EqualError(s.T(), err, fmt.Sprintf("Bad value for parameter 'parent resource ID': '%s' - resource with id '%s' not found", unknownParentID, unknownParentID))
}

func (s *resourceServiceBlackBoxTest) TestRegisterReadDeleteResourceWithoutParentOK() {
	resourceID := uuid.NewV4().String()

	// Register. No parent
	resource, err := s.resourceService.Register(context.Background(), authorization.ResourceTypeSpace, &resourceID, nil)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), resourceID, resource.ResourceID)
	assert.Equal(s.T(), "", resource.Name)
	assert.Equal(s.T(), "6422fda4-a0fa-4d3c-8b79-8061e5c05e12", resource.ResourceTypeID.String())
	assert.Equal(s.T(), authorization.ResourceTypeSpace, resource.ResourceType.Name)
	assert.Nil(s.T(), resource.ParentResourceID)
	assert.Nil(s.T(), resource.ParentResource)

	// Read
	r, err := s.resourceService.Read(context.Background(), resource.ResourceID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), r)
	require.NotNil(s.T(), r.ResourceID)
	assert.Equal(s.T(), resourceID, *r.ResourceID)
	assert.Equal(s.T(), authorization.ResourceTypeSpace, *r.Type)
	assert.Equal(s.T(), []string{"view", "contribute", "manage"}, r.ResourceScopes)

	// Delete
	err = s.resourceService.Delete(context.Background(), resource.ResourceID)
	require.NoError(s.T(), err)
}

func (s *resourceServiceBlackBoxTest) TestRegisterReadDeleteResourceWithParentOK() {
	resourceID := uuid.NewV4().String()

	// With parent resource
	g := s.DBTestSuite.NewTestGraph()
	g.CreateResource(g.ID("myparentresource"))
	parent := g.ResourceByID("myparentresource").Resource()
	resource, err := s.resourceService.Register(context.Background(), authorization.ResourceTypeSpace, &resourceID, &parent.ResourceID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), resourceID, resource.ResourceID)
	assert.Equal(s.T(), "", resource.Name)
	assert.Equal(s.T(), "6422fda4-a0fa-4d3c-8b79-8061e5c05e12", resource.ResourceTypeID.String())
	assert.Equal(s.T(), authorization.ResourceTypeSpace, resource.ResourceType.Name)
	assert.NotNil(s.T(), resource.ParentResourceID)
	assert.Equal(s.T(), parent.ResourceID, *resource.ParentResourceID)
	require.NotNil(s.T(), resource.ParentResource)
	assert.Equal(s.T(), parent.ResourceID, resource.ParentResource.ResourceID)

	// Read
	r, err := s.resourceService.Read(context.Background(), resource.ResourceID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), r)
	require.NotNil(s.T(), r.ResourceID)
	assert.Equal(s.T(), resourceID, *r.ResourceID)
	require.NotNil(s.T(), r.ParentResourceID)
	assert.Equal(s.T(), parent.ResourceID, *r.ParentResourceID)
	assert.Equal(s.T(), authorization.ResourceTypeSpace, *r.Type)
	assert.Equal(s.T(), []string{"view", "contribute", "manage"}, r.ResourceScopes)

	// Delete
	err = s.resourceService.Delete(context.Background(), resource.ResourceID)
	require.NoError(s.T(), err)
}

func (s *resourceServiceBlackBoxTest) TestReadUnknownResourceFails() {
	unknownResourceID := uuid.NewV4().String()
	_, err := s.resourceService.Read(context.Background(), unknownResourceID)
	require.EqualError(s.T(), err, fmt.Sprintf("resource with id '%s' not found", unknownResourceID))
}
