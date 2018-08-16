package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	resourceService service.ResourceService
}

func TestRunResourceServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.resourceService = s.Application.ResourceService()
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
	s.checkDeleteResource(resource.ResourceID)
}

func (s *resourceServiceBlackBoxTest) TestRegisterReadDeleteResourceWithParentOK() {
	resourceID := uuid.NewV4().String()

	// With parent resource
	g := s.DBTestSuite.NewTestGraph(s.T())
	g.CreateResource(g.ID("myparentresource"))
	parent := g.ResourceByID("myparentresource").Resource()
	resource, err := s.resourceService.Register(context.Background(), authorization.ResourceTypeSpace, &resourceID, &parent.ResourceID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), resourceID, resource.ResourceID)
	assert.Equal(s.T(), "", resource.Name)
	assert.Equal(s.T(), "6422fda4-a0fa-4d3c-8b79-8061e5c05e12", resource.ResourceTypeID.String())
	assert.Equal(s.T(), authorization.ResourceTypeSpace, resource.ResourceType.Name)
	require.NotNil(s.T(), resource.ParentResourceID)
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
	s.checkDeleteResource(resource.ResourceID)
}

func (s *resourceServiceBlackBoxTest) TestDeleteResourceOK() {

	// Create test data

	g := s.DBTestSuite.NewTestGraph(s.T())
	org := g.CreateOrganization()

	spaceToDelete := g.CreateSpace(org)
	spaceToDelete.AddAdmin(g.CreateUser(g.ID("admin-user")))

	teamToDeleteA := g.CreateTeam(spaceToDelete)
	teamToDeleteB := g.CreateTeam(spaceToDelete)

	childResourceToDelete := g.CreateResource(spaceToDelete)
	grandchildResourceToDelete := g.CreateResource(childResourceToDelete)

	spaceRoleMappingToDelete := g.CreateRoleMapping(spaceToDelete)
	grandchildRoleMappingToDelete := g.CreateRoleMapping(spaceToDelete)

	spaceToStay := g.CreateSpace(org).AddAdmin(g.CreateUser())
	teamToStay := g.CreateTeam(spaceToStay)
	spaceRoleMappingToStay := g.CreateRoleMapping(spaceToStay)

	// Check test data

	s.checkIdentity(true, teamToDeleteA.TeamID().String())
	s.checkIdentity(true, teamToDeleteB.TeamID().String())

	s.checkResource(true, spaceToDelete.SpaceID())
	s.checkResource(true, teamToDeleteA.ResourceID())
	s.checkResource(true, teamToDeleteB.ResourceID())
	s.checkResource(true, childResourceToDelete.ResourceID())
	s.checkResource(true, grandchildResourceToDelete.ResourceID())

	s.checkIdentityRole(1, spaceToDelete.SpaceID())

	s.checkRoleMapping(true, spaceRoleMappingToDelete.RoleMapping().RoleMappingID)
	s.checkRoleMapping(true, grandchildRoleMappingToDelete.RoleMapping().RoleMappingID)

	// Delete the space

	err := s.resourceService.Delete(s.Ctx, spaceToDelete.SpaceID())
	require.NoError(s.T(), err)

	// Check all related artifacts for the space are gone

	s.checkIdentity(false, teamToDeleteA.TeamID().String())
	s.checkIdentity(false, teamToDeleteB.TeamID().String())

	s.checkResource(false, spaceToDelete.SpaceID())
	s.checkResource(false, teamToDeleteA.ResourceID())
	s.checkResource(false, teamToDeleteB.ResourceID())

	s.checkResource(false, childResourceToDelete.ResourceID())
	s.checkResource(false, grandchildResourceToDelete.ResourceID())

	s.checkIdentityRole(0, spaceToDelete.SpaceID())
	s.checkIdentityRole(0, teamToDeleteA.ResourceID())
	s.checkIdentityRole(0, teamToDeleteB.ResourceID())

	s.checkRoleMapping(false, spaceRoleMappingToDelete.RoleMapping().RoleMappingID)
	s.checkRoleMapping(false, grandchildRoleMappingToDelete.RoleMapping().RoleMappingID)

	// Check all not-related artifacts are still present

	s.checkResource(true, spaceToStay.SpaceID())
	s.checkResource(true, teamToStay.ResourceID())

	s.checkIdentity(true, g.UserByID("admin-user").Identity().ID.String())
	s.checkIdentity(true, teamToStay.TeamID().String())

	s.checkIdentityRole(1, spaceToStay.SpaceID())

	s.checkRoleMapping(true, spaceRoleMappingToStay.RoleMapping().RoleMappingID)
}

func (s *resourceServiceBlackBoxTest) TestDeleteResourceWithCycleReferencesFails() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	parent := g.CreateResource()
	child := g.CreateResource(parent)
	childResourceID := child.ResourceID()
	parent.Resource().ParentResourceID = &childResourceID
	err := s.Application.ResourceRepository().Save(s.Ctx, parent.Resource())
	require.NoError(s.T(), err)

	err = s.resourceService.Delete(s.Ctx, parent.ResourceID())
	testsupport.AssertError(s.T(), err, errors.InternalError{}, "cycle resource references detected for resource %s with parent %s", parent.ResourceID(), child.ResourceID())
}

func (s *resourceServiceBlackBoxTest) checkRoleMapping(shouldExist bool, roleMappingID uuid.UUID) {
	err := s.Application.RoleMappingRepository().CheckExists(s.Ctx, roleMappingID)
	if shouldExist {
		assert.NoError(s.T(), err)
	} else {
		testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role_mapping with id '%s' not found", roleMappingID)
	}
}

func (s *resourceServiceBlackBoxTest) checkIdentityRole(expectedLen int, resourceID string) {
	roles, err := s.Application.IdentityRoleRepository().FindIdentityRolesByResource(s.Ctx, resourceID, false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), roles, expectedLen)
}

func (s *resourceServiceBlackBoxTest) checkIdentity(shouldExist bool, identityID string) {
	err := s.Application.Identities().CheckExists(s.Ctx, identityID)
	if shouldExist {
		assert.NoError(s.T(), err)
	} else {
		testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identities with id '%s' not found", identityID)
	}
}

func (s *resourceServiceBlackBoxTest) checkResource(shouldExist bool, resourceID string) {
	err := s.Application.ResourceRepository().CheckExists(s.Ctx, resourceID)
	if shouldExist {
		require.NoError(s.T(), err)
	} else {
		testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", resourceID)
	}
}

func (s *resourceServiceBlackBoxTest) TestReadUnknownResourceFails() {
	s.checkUnknownResourceID(uuid.NewV4().String())
}

func (s *resourceServiceBlackBoxTest) TestRoleMappingsCreated() {
	g := s.NewTestGraph(s.T())
	// Create a default role mapping for a new resource type
	id := uuid.NewV4()
	m := g.CreateDefaultRoleMapping(g.CreateResourceType(g.ID(id.String())))

	// Create another default role mapping for a different resource type
	id2 := uuid.NewV4()
	g.CreateDefaultRoleMapping(g.CreateResourceType(g.ID(id2.String())))

	// Register a resource with the same resource type as the default role mapping
	r, err := s.resourceService.Register(s.Ctx, g.ResourceTypeByID(id).ResourceType().Name, nil, nil)
	require.NoError(s.T(), err)

	// Find the mappings for the new resource
	mappings, err := s.Application.RoleMappingRepository().FindForResource(s.Ctx, r.ResourceID)
	require.NoError(s.T(), err)

	// We should have exactly 1 mapping
	require.Len(s.T(), mappings, 1)

	// It should have the same from role and to role values as the default mapping
	require.Equal(s.T(), m.DefaultRoleMapping().FromRoleID, mappings[0].FromRoleID)
	require.Equal(s.T(), m.DefaultRoleMapping().ToRoleID, mappings[0].ToRoleID)
}

func (s *resourceServiceBlackBoxTest) checkDeleteResource(resourceID string) {
	err := s.resourceService.Delete(context.Background(), resourceID)
	require.NoError(s.T(), err)
	s.checkUnknownResourceID(resourceID)
}

func (s *resourceServiceBlackBoxTest) checkUnknownResourceID(resourceID string) {
	_, err := s.resourceService.Read(context.Background(), resourceID)
	require.EqualError(s.T(), err, fmt.Sprintf("resource with id '%s' not found", resourceID))
}
