package authorization

import (
	"github.com/satori/go.uuid"
)

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

	// ManageMembersScope is the scope required for users wishing to invite/remove other users to an organization, team or security group
	ManageMembersScope = "manage_members"

	// ManageTeamsScope is the scope required for users wishing to manage teams for a space
	ManageTeamsInSpaceScope = "manage"
)

// CanHaveMembers returns a boolean indicating whether the specified resource type may have member Identities
func CanHaveMembers(resourceTypeName string) bool {
	return resourceTypeName == IdentityResourceTypeOrganization ||
		resourceTypeName == IdentityResourceTypeTeam ||
		resourceTypeName == IdentityResourceTypeGroup
}

// IdentityAssociation represents an association between an Identity and either another Identity or a Resource, whether by
// membership or by having been granted a role.  It contains metadata about the Identity's relationship with the other
// entity, including its membership state, and any roles it may have been assigned.
type IdentityAssociation struct {
	ResourceID   string
	ResourceName string
	IdentityID   *uuid.UUID
	Member       bool
	Roles        []string
}

// AppendAssociation appends the association state specified by the parameter values to an existing IdentityAssociation array
func AppendAssociation(associations []IdentityAssociation, resourceID string, resourceName *string, identityID *uuid.UUID, member bool, role *string) []IdentityAssociation {
	found := false
	for i, assoc := range associations {
		if assoc.ResourceID == resourceID {
			found = true

			if assoc.IdentityID == nil && identityID != nil {
				assoc.IdentityID = identityID
			}

			if !assoc.Member && member {
				assoc.Member = true
			}

			if role != nil {
				roleFound := false
				for _, r := range assoc.Roles {
					if r == *role {
						roleFound = true
						break
					}
				}

				if !roleFound {
					assoc.Roles = append(assoc.Roles, *role)
				}
			}

			associations[i] = assoc
			break
		}
	}

	if !found {
		roles := []string{}
		if role != nil {
			roles = append(roles, *role)
		}
		associations = append(associations, IdentityAssociation{
			ResourceID:   resourceID,
			ResourceName: *resourceName,
			IdentityID:   identityID,
			Member:       member,
			Roles:        roles,
		})
	}

	return associations
}

// MergeAssociations merges two arrays of IdentityAssociation objects into one
func MergeAssociations(associations []IdentityAssociation, merge []IdentityAssociation) []IdentityAssociation {
	for _, merging := range merge {
		found := false
		for i, assoc := range associations {
			// there is a match if the record to be merged has the same ResourceID (there must always be a resource)
			if assoc.ResourceID == merging.ResourceID {
				found = true

				assoc.Member = merging.Member

				if assoc.IdentityID == nil && merging.IdentityID != nil {
					assoc.IdentityID = merging.IdentityID
				}

				for _, roleToMerge := range merging.Roles {
					roleFound := false

					for _, assocRole := range assoc.Roles {
						if assocRole == roleToMerge {
							roleFound = true
							break
						}
					}

					if !roleFound {
						assoc.Roles = append(assoc.Roles, roleToMerge)
					}
				}

				associations[i] = assoc
			}
		}

		if !found {
			associations = append(associations, merging)
		}
	}

	return associations
}
