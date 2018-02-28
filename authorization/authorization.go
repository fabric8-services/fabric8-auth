package authorization

const (
	// IdentityResourceTypeOrganization defines the string constant to be used for denoting an organization managed by the authorization framework
	IdentityResourceTypeOrganization = "identity/organization"

	// IdentityResourceTypeTeam defines the string constant to be used for denoting a team managed by the authorization framework
	IdentityResourceTypeTeam = "identity/team"

	// IdentityResourceTypeGroup defines the string constant to be used for denoting a group managed by the authorization framework
	IdentityResourceTypeGroup = "identity/group"

	// IdentityResourceTypeUser defines the string constant to be used for denoting a user managed by the authorization framework
	IdentityResourceTypeUser = "identity/user"

	// OwnerRole is the constant used to denote the name of the organization, team or security group owner role
	OwnerRole = "owner"

	// InviteUserScope is the scope required for users wishing to invite other users to an organization, team or security group
	InviteUserScope = "invite_user"
)
