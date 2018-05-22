package service_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type organizationServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	identityRepo     account.IdentityRepository
	identityRoleRepo role.IdentityRoleRepository
	resourceRepo     resource.ResourceRepository
	orgService       service.OrganizationService
}

func TestRunOrganizationServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &organizationServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *organizationServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.identityRoleRepo = role.NewIdentityRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)

	s.orgService = s.Application.OrganizationService()
}

func (s *organizationServiceBlackBoxTest) TestCreateOrganization() {
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationServiceBlackBoxTest-TestCreateOrganization")
	require.Nil(s.T(), err, "Could not create identity")

	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZXYAAA")
	require.Nil(s.T(), err, "Could not create organization")

	// Load the organization's identity
	orgIdentity, err := s.identityRepo.Load(s.Ctx, *orgId)
	require.Nil(s.T(), err, "Could not load organization's identity")

	// Assert that the identity resource ID is set
	require.True(s.T(), orgIdentity.IdentityResourceID.Valid, "Organization identity's resource id is nil")
	require.NotEmpty(s.T(), orgIdentity.IdentityResourceID.String, "Organization identity's resource id is not set")

	// Load the organization's resource
	orgResource, err := s.resourceRepo.Load(s.Ctx, orgIdentity.IdentityResourceID.String)
	require.Nil(s.T(), err, "Could not load the organization's resource")

	require.Equal(s.T(), authorization.IdentityResourceTypeOrganization, orgResource.ResourceType.Name, "Organization resource type is invalid")

	require.Equal(s.T(), orgResource.Name, "Test Organization ZXYAAA")

	rows, err := s.DB.Raw("SELECT r.name FROM identities i, identity_role ir, role r 	WHERE i.identity_resource_id = ir.resource_id and ir.role_id = r.role_id and i.id = ?", *orgId).Rows()
	defer rows.Close()
	roleCount := 0
	for rows.Next() {
		var roleName string
		rows.Scan(&roleName)

		require.Equal(s.T(), authorization.OwnerRole, roleName, "Only 'owner' role should be assigned during organization creation")
		roleCount++
	}

	require.Equal(s.T(), 1, roleCount, "Found more than 1 role")
}

func (s *organizationServiceBlackBoxTest) TestListOrganization() {
	identityOwner, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationServiceBlackBoxTest-TestListOrganization")
	require.Nil(s.T(), err, "Could not create identity")

	identityAnother, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "organizationServiceBlackBoxTest-TestListOrganization2")
	require.Nil(s.T(), err, "Could not create identity")

	// Orgs created by the first user
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identityOwner.ID, "Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")
	orgId2, err := s.orgService.CreateOrganization(s.Ctx, identityOwner.ID, "One More Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")

	// Org created by the second user
	_, err = s.orgService.CreateOrganization(s.Ctx, identityAnother.ID, "Yet One More Test Organization")
	require.Nil(s.T(), err, "Could not create organization")

	// Load orgs where the first user is a member
	orgs, err := s.orgService.ListOrganizations(s.Ctx, identityOwner.ID)
	require.Nil(s.T(), err, "Could not list organizations")

	// Check we get two organizations back
	require.Equal(s.T(), 2, len(orgs), "Did not get exactly 2 organizations in list")

	s.equalOrganization(*orgId, "Test Organization MMMYYY", s.findOrganizationWithID(*orgId, orgs))
	s.equalOrganization(*orgId2, "One More Test Organization MMMYYY", s.findOrganizationWithID(*orgId2, orgs))
}

func (s *organizationServiceBlackBoxTest) findOrganizationWithID(orgId uuid.UUID, orgs []authorization.IdentityAssociation) *authorization.IdentityAssociation {
	for _, org := range orgs {
		if *org.IdentityID == orgId {
			return &org
		}
	}
	return nil
}

func (s *organizationServiceBlackBoxTest) equalOrganization(expectedOrgID uuid.UUID, expectedOrgName string, actualOrg *authorization.IdentityAssociation) {
	require.NotNil(s.T(), actualOrg, "Organization is nil")
	require.Equal(s.T(), expectedOrgID, *actualOrg.IdentityID, "Organization ID is different")
	require.Equal(s.T(), false, actualOrg.Member, "User should not be a member of newly created organization")
	require.Equal(s.T(), expectedOrgName, actualOrg.ResourceName, "Organization name is different")
	require.Equal(s.T(), 1, len(actualOrg.Roles), "New organization should have assigned exactly 1 role")
	require.Equal(s.T(), authorization.OwnerRole, actualOrg.Roles[0], "New organization should have assigned owner role")
}
