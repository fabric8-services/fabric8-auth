package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	roletestsupport "github.com/fabric8-services/fabric8-auth/authorization/role/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestResourceRolesRest struct {
	gormtestsupport.DBTestSuite
}

func (s *TestResourceRolesRest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
}

func (rest *TestResourceRolesRest) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUser("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, rest.Application)
}

func TestRunResourceRolesRest(t *testing.T) {
	suite.Run(t, &TestResourceRolesRest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceRolesRest) TestListAssignedRolesOK() {

	// Create a role for the inbuild resource type
	// Create a resource of the inbuilt resource type
	// Create two assignments for that role.

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)

	// assigned roles for this should not be returned.
	resourceRefUnrelated, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceRUnrelated", nil)
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	// this assigned role should not be returned when we later
	// on list the assigned roles.
	identityRoleRefUnrelated, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRefUnrelated, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRefUnrelated)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRefUnrelated)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, false))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, false))
}

func (rest *TestResourceRolesRest) TestListAssignedRolesNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	test.ListAssignedResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, uuid.NewV4().String(), uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesFromInheritedOK() {

	// Create a resource of the inbuilt resource type
	// Create a child resource of the above resource
	// Create a role for that resource type
	// Create two assignments for that role
	// Validate for 'Inherited' field's response

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), parentResourceRef)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceH", &parentResourceRef.ResourceID)
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, true))
}

func (rest *TestResourceRolesRest) TestAssignRoleOK() {
	// create a resource
	r, err := testsupport.CreateTestResourceWithRandomResourceType(rest.Ctx, rest.DB, uuid.NewV4().String(), nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), r)

	identitiesToBeAssigned, _ := roletestsupport.CreateRandomResourceMembers(rest.T(), rest.DB, *r, nil)

	// Create a user who has the privileges to assign roles

	ir := roletestsupport.CreateAdministratorAssignment(rest.T(), rest.DB, *r)

	svc, ctrl := rest.SecuredControllerWithIdentity(ir.Identity)
	payload := app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	// before
	newRoleScope := roletestsupport.SetupNewRole(rest.T(), rest.DB, *r, uuid.NewV4().String(), uuid.NewV4().String())
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, r.ResourceID, newRoleScope.Role.Name)

	// lets assign 10 people now
	test.AssignRoleResourceRolesNoContent(rest.T(), svc.Context, svc, ctrl, r.ResourceID, newRoleScope.Role.Name, &payload)

	// after
	_, roleListResp := test.ListAssignedByRoleNameResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, r.ResourceID, newRoleScope.Role.Name)
	require.Len(rest.T(), roleListResp.Data, 10)
	for _, createdIdentity := range identitiesToBeAssigned {
		require.True(rest.T(), rest.checkIdentityExistsInAssignmentList(createdIdentity.ID, roleListResp))
	}
}

func (rest *TestResourceRolesRest) TestAssignRoleForbiddenUserNotInSpace() {
	// create a resource type
	rt, err := testsupport.CreateTestResourceType(rest.Ctx, rest.DB, uuid.NewV4().String())
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), rt)

	// create a resource
	r, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *rt, uuid.NewV4().String(), nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), r)

	// create a role 'special_admin'
	adminRole, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *rt, uuid.NewV4().String())
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminRole)

	// create a scope 'assign_role'
	adminScope, err := testsupport.CreateTestScope(rest.Ctx, rest.DB, *rt, "assign_role")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminScope)

	// associate role and scope
	adminRoleScope, err := testsupport.CreateTestRoleScope(rest.Ctx, rest.DB, *adminScope, *adminRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminRoleScope)

	ir, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *r, *adminRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), ir)

	// create a role 'contributor'
	contributorRole, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *rt, "contributor")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorRole)

	// create a scope 'edit_workitem'
	contributorScope, err := testsupport.CreateTestScope(rest.Ctx, rest.DB, *rt, "edit_workitem")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorScope)

	// associate role and scope
	contributorRoleScope, err := testsupport.CreateTestRoleScope(rest.Ctx, rest.DB, *contributorScope, *contributorRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorRoleScope)

	var identitiesToBeAssigned []*app.UpdateUserID

	for i := 0; i < 10; i++ {

		// create an identity
		identityToBeAssigned, err := testsupport.CreateTestIdentityAndUser(rest.DB, uuid.NewV4().String(), "KC")
		require.NoError(rest.T(), err)
		require.NotNil(rest.T(), identityToBeAssigned)

		identityPayload := app.UpdateUserID{
			ID:   identityToBeAssigned.ID.String(),
			Type: "identities",
		}
		identitiesToBeAssigned = append(identitiesToBeAssigned, &identityPayload)

	}

	// try to assign that identity with the role
	svc, ctrl := rest.SecuredControllerWithIdentity(ir.Identity)
	payload := app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}
	test.AssignRoleResourceRolesForbidden(rest.T(), svc.Context, svc, ctrl, r.ResourceID, contributorRole.Name, &payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleForbiddenNotAllowedToAssignRoles() {
	// create a resource type
	rt, err := testsupport.CreateTestResourceType(rest.Ctx, rest.DB, uuid.NewV4().String())
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), rt)

	// create a resource
	r, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *rt, uuid.NewV4().String(), nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), r)

	// create a admin like role, but not exactly the one needed
	adminRole, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *rt, uuid.NewV4().String())
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminRole)

	adminScope, err := testsupport.CreateTestScope(rest.Ctx, rest.DB, *rt, "not_allowed_to_assign_role")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminScope)

	adminRoleScope, err := testsupport.CreateTestRoleScope(rest.Ctx, rest.DB, *adminScope, *adminRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), adminRoleScope)

	ir, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *r, *adminRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), ir)

	// create a role 'contributor'
	contributorRole, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *rt, "contributor")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorRole)

	// create a scope 'edit_workitem'
	contributorScope, err := testsupport.CreateTestScope(rest.Ctx, rest.DB, *rt, "edit_workitem")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorScope)

	// associate role and scope
	contributorRoleScope, err := testsupport.CreateTestRoleScope(rest.Ctx, rest.DB, *contributorScope, *contributorRole)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), contributorRoleScope)

	var identitiesToBeAssigned []*app.UpdateUserID

	for i := 0; i < 10; i++ {

		// create an identity
		identityToBeAssigned, err := testsupport.CreateTestIdentityAndUser(rest.DB, uuid.NewV4().String(), "KC")
		require.NoError(rest.T(), err)
		require.NotNil(rest.T(), identityToBeAssigned)

		identityPayload := app.UpdateUserID{
			ID:   identityToBeAssigned.ID.String(),
			Type: "identities",
		}
		identitiesToBeAssigned = append(identitiesToBeAssigned, &identityPayload)

	}

	// try to assign that identity with the role
	svc, ctrl := rest.SecuredControllerWithIdentity(ir.Identity)
	payload := app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}
	test.AssignRoleResourceRolesForbidden(rest.T(), svc.Context, svc, ctrl, r.ResourceID, contributorRole.Name, &payload)
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameFromInheritedOK() {

	// Create a resource of the inbuilt resource type
	// Create a child resource of the above resource
	// Create a role for that resource type
	// Create two assignments for that role
	// Validate for 'Inherited' field's response

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), parentResourceRef)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceH", &parentResourceRef.ResourceID)
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	roleRefGroup2, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole
	var createdIdentityRolesGroup2 []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	// second role

	identityRoleRef1InGroup2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRefGroup2)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef1InGroup2)
	createdIdentityRolesGroup2 = append(createdIdentityRolesGroup2, *identityRoleRef1InGroup2)

	identityRoleRef2InGroup2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRefGroup2)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2InGroup2)
	createdIdentityRolesGroup2 = append(createdIdentityRolesGroup2, *identityRoleRef2InGroup2)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedByRoleNameResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, roleRef.Name)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, true))

	_, returnedIdentityRoles = test.ListAssignedByRoleNameResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, roleRefGroup2.Name)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef1InGroup2, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2InGroup2, returnedIdentityRoles, true))

	// include these as a side-test
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) checkExists(createdRole role.IdentityRole, pool *app.Identityroles, isInherited bool) bool {
	for _, retrievedRole := range pool.Data {
		if retrievedRole.AssigneeID == createdRole.IdentityID.String() {
			rest.compare(createdRole, *retrievedRole, isInherited)
			return true
		}
	}
	return false
}

func (rest *TestResourceRolesRest) compare(createdRole role.IdentityRole, retrievedRole app.IdentityRolesData, isInherited bool) bool {
	require.Equal(rest.T(), createdRole.IdentityID.String(), retrievedRole.AssigneeID)
	require.Equal(rest.T(), createdRole.Role.Name, retrievedRole.RoleName)
	require.Equal(rest.T(), "user", retrievedRole.AssigneeType)
	if isInherited {
		require.True(rest.T(), retrievedRole.Inherited)
		require.NotNil(rest.T(), createdRole.Resource.ParentResourceID)
		require.Equal(rest.T(), *createdRole.Resource.ParentResourceID, *createdRole.Resource.ParentResourceID)
	} else {
		require.False(rest.T(), retrievedRole.Inherited)
	}
	return true
}

func (rest *TestResourceRolesRest) checkIdentityExistsInAssignmentList(createdIdentity string, pool *app.Identityroles) bool {
	for _, retrievedRole := range pool.Data {
		if retrievedRole.AssigneeID == createdIdentity {
			return true
		}
	}
	return false
}
