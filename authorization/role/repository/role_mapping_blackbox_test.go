package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	resourcetyperepo "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleMappingBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo rolerepo.RoleMappingRepository
}

func TestRunRoleMappingBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleMappingBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleMappingBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = rolerepo.NewRoleMappingRepository(s.DB)
}

func (s *roleMappingBlackBoxTest) TestOKToDelete() {

	rm1, err := s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "role_mapping_test_role_employee", authorization.IdentityResourceTypeTeam, "role_mapping_test_role_member")
	require.NoError(s.T(), err)

	_, err = s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "role_mapping_test_role_manager", authorization.IdentityResourceTypeGroup, "role_mapping_test_role_admin")
	require.NoError(s.T(), err)

	mappings, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list role mappings")

	require.Equal(s.T(), 2, len(mappings))

	err = s.repo.Delete(s.Ctx, rm1.RoleMappingID)
	assert.Nil(s.T(), err)

	// there should be one mapping now
	mappings, err = s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list role mappings")
	require.Equal(s.T(), 1, len(mappings))

	for _, data := range mappings {
		// The role mapping rm1 was deleted while rm2 was not deleted, hence we check
		// that none of the role mappings returned include the deleted record.
		require.NotEqual(s.T(), rm1.RoleMappingID.String(), data.RoleMappingID.String())
	}
}

func (s *roleMappingBlackBoxTest) createTestRoleMapping(fromResourceTypeName string, fromRoleName string, toResourceTypeName string, toRoleName string) (rolerepo.RoleMapping, error) {
	resourceTypeRepo := resourcetyperepo.NewResourceTypeRepository(s.DB)

	var rm rolerepo.RoleMapping

	fromResourceType, err := resourceTypeRepo.Lookup(s.Ctx, fromResourceTypeName)
	if err != nil {
		return rm, err
	}

	toResourceType, err := resourceTypeRepo.Lookup(s.Ctx, toResourceTypeName)
	if err != nil {
		return rm, err
	}

	fromRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *fromResourceType, fromRoleName)
	if err != nil {
		return rm, err
	}

	toRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *toResourceType, toRoleName)
	if err != nil {
		return rm, err
	}

	resource, err := testsupport.CreateTestResource(s.Ctx, s.DB, *fromResourceType, "Test-Role-Mapped-Resource"+uuid.NewV4().String(), nil)
	if err != nil {
		return rm, err
	}

	rm = rolerepo.RoleMapping{
		ResourceID: resource.ResourceID,
		FromRoleID: fromRole.RoleID,
		ToRoleID:   toRole.RoleID,
	}

	err = s.repo.Create(s.Ctx, &rm)
	return rm, err
}

func (s *roleMappingBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role_mapping with id '%s' not found", id.String())
}

func (s *roleMappingBlackBoxTest) TestOKToLoad() {
	rm1, err := s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "role_mapping_test_role_personnel", authorization.IdentityResourceTypeTeam, "role_mapping_test_role_member")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rm1)

	_, err = s.repo.Load(s.Ctx, rm1.RoleMappingID)
	require.NoError(s.T(), err)
}

func (s *roleMappingBlackBoxTest) TestExistsRoleMapping() {
	rm1, err := s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "role_mapping_test_role_staff", authorization.IdentityResourceTypeTeam, "role_mapping_test_role_someOtherRoleName")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rm1)

	_, err = s.repo.CheckExists(s.Ctx, rm1.RoleMappingID)
	require.NoError(s.T(), err)
}

func (s *roleMappingBlackBoxTest) TestOKToSave() {
	otherResource, err := testsupport.CreateTestResourceWithDefaultType(s.Ctx, s.DB, "other-resource")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), otherResource)

	rm1, err := s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "role_mapping_test_role_contributor", authorization.IdentityResourceTypeTeam, "role_mapping_test_role_committer")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rm1)

	rm1.ResourceID = otherResource.ResourceID
	err = s.repo.Save(s.Ctx, &rm1)
	require.Nil(s.T(), err, "Could not update role mapping")

	updatedRm, err := s.repo.Load(s.Ctx, rm1.RoleMappingID)
	require.Nil(s.T(), err, "Could not load role mapping")
	require.Equal(s.T(), rm1.ResourceID, updatedRm.ResourceID)
}

func (s *roleMappingBlackBoxTest) TestFindForResource() {
	g := s.NewTestGraph()

	m := g.CreateRoleMapping(g.CreateResource(g.ID("r")))

	// make some noise!!
	for i := 0; i < 10; i++ {
		g.CreateRoleMapping()
	}

	mappings, err := s.repo.FindForResource(s.Ctx, g.ResourceByID("r").Resource().ResourceID)
	require.NoError(s.T(), err)

	require.Len(s.T(), mappings, 1)
	require.Equal(s.T(), m.RoleMapping().FromRoleID, mappings[0].FromRoleID)
	require.Equal(s.T(), m.RoleMapping().ToRoleID, mappings[0].ToRoleID)
}
