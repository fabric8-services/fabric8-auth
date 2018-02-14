package model_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/common"
	"github.com/fabric8-services/fabric8-auth/authorization/model"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type organizationModelServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resource.ResourceRepository
	identityRepo     account.IdentityRepository
	identityRoleRepo role.IdentityRoleRepository
	resourceRepo     resource.ResourceRepository
	resourceTypeRepo resource.ResourceTypeRepository
	roleRepo         role.RoleRepository
	orgModelService  model.OrganizationModelService
}

func TestRunOrganizationModelServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &organizationModelServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *organizationModelServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resource.NewResourceRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.identityRoleRepo = role.NewIdentityRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)

	s.orgModelService = model.NewOrganizationModelService(s.DB, &test.TestRepositories{
		FIdentityRepository:     s.identityRepo,
		FIdentityRoleRepository: s.identityRoleRepo,
		FResourceRepository:     s.resourceRepo,
		FResourceTypeRepository: s.resourceTypeRepo,
		FRoleRepository:         s.roleRepo,
	})
}

func (s *organizationModelServiceBlackBoxTest) TestCreateOrganization() {
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationModelServiceBlackBoxTest-TestCreateOrganization")
	require.Nil(s.T(), err, "Could not create identity")

	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZXYAAA")
	require.Nil(s.T(), err, "Could not create organization")

	// Load the organization's identity
	orgIdentity, err := s.identityRepo.Load(s.Ctx, *orgId)
	require.Nil(s.T(), err, "Could not load organization's identity")

	// Assert that the identity resource ID is set
	require.NotNil(s.T(), orgIdentity.IdentityResourceID, "Organization identity's resource id is nil")
	require.NotEmpty(s.T(), orgIdentity.IdentityResourceID, "Organization identity's resource id is not set")

	// Load the organization's resource
	orgResource, err := s.resourceRepo.Load(s.Ctx, *orgIdentity.IdentityResourceID)
	require.Nil(s.T(), err, "Could not load the organization's resource")

	require.Equal(s.T(), common.IdentityResourceTypeOrganization, orgResource.ResourceType.Name, "Organization resource type is invalid")

	require.Equal(s.T(), orgResource.Name, "Test Organization ZXYAAA")

	rows, err := s.DB.Raw("SELECT r.name FROM identities i, identity_role ir, role r 	WHERE i.identity_resource_id = ir.resource_id and ir.role_id = r.role_id and i.id = ?", *orgId).Rows()
	defer rows.Close()
	roleCount := 0
	for rows.Next() {
		var roleName string
		rows.Scan(&roleName)

		require.Equal(s.T(), common.OrganizationOwnerRole, roleName, "Only 'owner' role should be assigned during organization creation")
		roleCount++
	}

	require.Equal(s.T(), 1, roleCount, "Found more than 1 role")
}

func (s *organizationModelServiceBlackBoxTest) TestListOrganization() {
	identityOwner, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationModelServiceBlackBoxTest-TestListOrganization")
	require.Nil(s.T(), err, "Could not create identity")

	identityAnother, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationModelServiceBlackBoxTest-TestListOrganization2")
	require.Nil(s.T(), err, "Could not create identity")

	// Orgs created by the first user
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identityOwner.ID, "Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")
	orgId2, err := s.orgModelService.CreateOrganization(s.Ctx, identityOwner.ID, "One More Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")

	// Org created by the second user
	_, err = s.orgModelService.CreateOrganization(s.Ctx, identityAnother.ID, "One More Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")

	// Load orgs where the first user is a member
	orgs, err := s.orgModelService.ListOrganizations(s.Ctx, identityOwner.ID)
	require.Nil(s.T(), err, "Could not list organizations")

	// Check we get two organizations back
	require.Equal(s.T(), 2, len(orgs), "Did not get exactly 2 organizations in list")

	s.equalOrganization(*orgId, "Test Organization MMMYYY", s.findOrganizationWithID(*orgId, orgs))
	s.equalOrganization(*orgId2, "One More Test Organization MMMYYY", s.findOrganizationWithID(*orgId2, orgs))
}

func (s *organizationModelServiceBlackBoxTest) findOrganizationWithID(orgId uuid.UUID, orgs []common.IdentityOrganization) *common.IdentityOrganization {
	for _, org := range orgs {
		if org.OrganizationID == orgId {
			return &org
		}
	}
	return nil
}

func (s *organizationModelServiceBlackBoxTest) equalOrganization(expectedOrgID uuid.UUID, expectedOrgName string, actualOrg *common.IdentityOrganization) {
	require.NotNil(s.T(), actualOrg, "Organization is nil")
	require.Equal(s.T(), expectedOrgID, actualOrg.OrganizationID, "Organization ID is different")
	require.Equal(s.T(), false, actualOrg.Member, "User should not be a member of newly created organization")
	require.Equal(s.T(), expectedOrgName, actualOrg.Name, "Organization name is different")
	require.Equal(s.T(), 1, len(actualOrg.Roles), "New organization should have assigned exactly 1 role")
	require.Equal(s.T(), common.OrganizationOwnerRole, actualOrg.Roles[0], "New organization should have assigned owner role")
}
