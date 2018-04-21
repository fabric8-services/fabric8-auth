package service

import (
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
)

//Services creates instances of service layer objects
type Services interface {
	InvitationService() invitationservice.InvitationService
	PermissionService() permissionservice.PermissionService
	RoleManagementService() roleservice.RoleManagementService
}
