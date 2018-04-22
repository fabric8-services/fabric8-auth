package test

import (
	"testing"

	"context"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/require"
)

func SetupAdministratorRole(t *testing.T, db *gorm.DB, res resource.Resource) role.RoleScope {
	return SetupNewRole(t, db, res, uuid.NewV4().String(), "assign_role")

}

func SetupNewRole(t *testing.T, db *gorm.DB, res resource.Resource, roleName string, scopeName string) role.RoleScope {
	rt := res.ResourceType

	createdRole, err := testsupport.CreateTestRole(context.Background(), db, rt, roleName)
	require.NoError(t, err)
	require.NotNil(t, createdRole)

	createdScope, err := testsupport.CreateTestScope(context.Background(), db, rt, scopeName)
	require.NoError(t, err)
	require.NotNil(t, createdScope)

	// associate role and scope
	createdRoleScope, err := testsupport.CreateTestRoleScope(context.Background(), db, *createdScope, *createdRole)
	require.NoError(t, err)
	require.NotNil(t, createdRoleScope)

	return *createdRoleScope
}

func CreateAdministratorAssignment(t *testing.T, db *gorm.DB, res resource.Resource) role.IdentityRole {

	adminRoleScope := SetupAdministratorRole(t, db, res)

	ir, err := testsupport.CreateTestIdentityRole(context.Background(), db, res, adminRoleScope.Role)
	require.NoError(t, err)
	require.NotNil(t, ir)

	return *ir
}

func CreateRandomResourceMemberWithRole(t *testing.T, db *gorm.DB, res resource.Resource, roleToBeAssigned role.Role) *role.IdentityRole {

	ir, err := testsupport.CreateTestIdentityRole(context.Background(), db, res, roleToBeAssigned)
	require.NoError(t, err)
	require.NotNil(t, ir)

	return ir

}

func CreateRandomResourceMember(t *testing.T, db *gorm.DB, res resource.Resource) *role.IdentityRole {

	rt := res.ResourceType

	// add her to the space
	// create a role 'my_random_role'
	randomRole, err := testsupport.CreateTestRole(context.Background(), db, rt, uuid.NewV4().String())
	require.NoError(t, err)
	require.NotNil(t, randomRole)

	// create a scope 'my_random_scope'
	randomScope, err := testsupport.CreateTestScope(context.Background(), db, rt, uuid.NewV4().String())
	require.NoError(t, err)
	require.NotNil(t, randomScope)

	// associate role and scope
	randomRoleScope, err := testsupport.CreateTestRoleScope(context.Background(), db, *randomScope, *randomRole)
	require.NoError(t, err)
	require.NotNil(t, randomRoleScope)

	ir, err := testsupport.CreateTestIdentityRole(context.Background(), db, res, *randomRole)
	require.NoError(t, err)
	require.NotNil(t, ir)

	return ir
}

func CreateRandomResourceMembers(t *testing.T, db *gorm.DB, res resource.Resource, roleToBeAssigned *role.Role) ([]*app.UpdateUserID, []*account.Identity) {

	var identitiesToBeAssignedPayload []*app.UpdateUserID
	var identitiesToBeAssigned []*account.Identity

	for i := 0; i < 10; i++ {

		var ir *role.IdentityRole
		if roleToBeAssigned != nil {
			ir = CreateRandomResourceMemberWithRole(t, db, res, *roleToBeAssigned)
		} else {
			ir = CreateRandomResourceMember(t, db, res)
		}
		require.NotNil(t, ir)

		identityPayload := app.UpdateUserID{
			ID:   ir.Identity.ID.String(),
			Type: "identities",
		}
		identitiesToBeAssignedPayload = append(identitiesToBeAssignedPayload, &identityPayload)
		identitiesToBeAssigned = append(identitiesToBeAssigned, &ir.Identity)
	}
	return identitiesToBeAssignedPayload, identitiesToBeAssigned
}
