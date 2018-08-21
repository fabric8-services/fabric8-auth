package role

// RoleDescriptor is a DTO used to pass role information between the service layer and controller layer
type RoleDescriptor struct {
	RoleID       string
	RoleName     string
	Scopes       []string
	ResourceType string
}

// ResourceRoleDescriptor is a DTO used to pass role on resource information between the service layer and controller layer
type ResourceRoleDescriptor struct {
	RoleID       string
	RoleName     string
	Scopes       []string
	ResourceID   string
	ResourceType string
}
