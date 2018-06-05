package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/lib/pq"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type spaceServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunSpaceServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &spaceServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *spaceServiceBlackBoxTest) TestCreateByUnknownUserFails() {
	id := uuid.NewV4()
	err := s.Application.SpaceService().CreateSpace(s.Ctx, id, uuid.NewV4().String())
	test.AssertError(s.T(), err, errors.NotFoundError{}, "identity with id '%s' not found", id.String())
}

func (s *spaceServiceBlackBoxTest) TestCreateOK() {
	spaceID := uuid.NewV4().String()
	g := s.DBTestSuite.NewTestGraph()
	creator := g.CreateUser()

	err := s.Application.SpaceService().CreateSpace(s.Ctx, creator.Identity().ID, spaceID)
	require.NoError(s.T(), err)

	// Check if the corresponding authZ resource has been created
	resource, err := s.Application.ResourceService().Read(s.Ctx, spaceID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), spaceID, *resource.ResourceID)
	assert.Equal(s.T(), authorization.ResourceTypeSpace, *resource.Type)

	// Check the admin role has been assigned to the space creator
	assignedRoles, err := s.Application.RoleManagementService().ListByResource(s.Ctx, spaceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), assignedRoles, 1)
	assert.Equal(s.T(), creator.Identity().ID, assignedRoles[0].Identity.ID)
	assert.Equal(s.T(), authorization.SpaceAdminRole, assignedRoles[0].Role.Name)

	// If we try to create another space with the same ID it should fail
	err = s.Application.SpaceService().CreateSpace(s.Ctx, creator.Identity().ID, spaceID)
	test.AssertError(s.T(), err, &pq.Error{}, "pq: duplicate key value violates unique constraint \"resource_pkey\"")
}

func (s *spaceServiceBlackBoxTest) TestDeleteUnknownSpaceFails() {
	g := s.DBTestSuite.NewTestGraph()
	spaceID := uuid.NewV4().String()

	err := s.Application.SpaceService().DeleteSpace(s.Ctx, g.CreateUser().Identity().ID, spaceID)
	test.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", spaceID)
}

func (s *spaceServiceBlackBoxTest) TestByUnauthorizedUserFails() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace()
	user := g.CreateUser()

	err := s.Application.SpaceService().DeleteSpace(s.Ctx, user.Identity().ID, space.SpaceID())
	test.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", user.Identity().ID.String(), space.SpaceID())

	space.AddViewer(user)
	err = s.Application.SpaceService().DeleteSpace(s.Ctx, user.Identity().ID, space.SpaceID())
	test.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", user.Identity().ID.String(), space.SpaceID())

	space.AddContributor(user)
	err = s.Application.SpaceService().DeleteSpace(s.Ctx, user.Identity().ID, space.SpaceID())
	test.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", user.Identity().ID.String(), space.SpaceID())
}

func (s *spaceServiceBlackBoxTest) TestDeleteOK() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	space := g.CreateSpace().AddAdmin(user)

	err := s.Application.SpaceService().DeleteSpace(s.Ctx, user.Identity().ID, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the space is gone
	_, err = s.Application.ResourceService().Read(s.Ctx, space.SpaceID())
	test.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", space.SpaceID())
}
