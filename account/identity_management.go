package account

import (
	"context"
	uuid "github.com/satori/go.uuid"
)

const (
	IdentityResourceTypeOrganization = "identity/organization"
	IdentityResourceTypeTeam         = "identity/team"
	IdentityResourceTypeGroup        = "identity/group"
	IdentityResourceTypeUser         = "identity/user"
)

// This struct is used to return the Organizations for which an Identity is associated
type IdentityOrganization struct {
	OrganizationID uuid.UUID
	Name           string
	Member         bool
	Roles          []string
}

// Returns an array of all organizations in which the specified user is a member or is assigned a role
func (m *GormIdentityRepository) ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]IdentityOrganization, error) {

	db := m.db.Model(&Identity{})

	findOrganization := func(orgs []IdentityOrganization, id uuid.UUID) int {
		for i, org := range orgs {
			if org.OrganizationID == id {
				return i
			}
		}
		return -1
	}

	results := []IdentityOrganization{}

	// query for organizations in which the user is a member
	rows, err := db.Unscoped().Raw(`SELECT 
      oi.ID,
      r.name
    FROM 
      resource r, 
      identities oi, 
      resource_type rt
		WHERE 
      oi.identity_resource_id = r.resource_id 
      and r.resource_type_id = rt.resource_type_id
		  and rt.name = ? 
      and oi.deleted_at IS NULL
      and r.deleted_at IS NULL
      and rt.deleted_at IS NULL
      and (oi.ID = ? 
      OR oi.ID in (
        WITH RECURSIVE m AS (
		      SELECT 
            member_of 
          FROM 
            membership 
          WHERE 
            member_id = ? 
          UNION SELECT 
            p.member_of 
          FROM 
            membership p INNER JOIN m ON m.member_of = p.member_id
        ) 
        select member_of from m
      ))`,
		IdentityResourceTypeOrganization, identityID, identityID).Rows()

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var id string
		var name string
		rows.Scan(&id, &name)
		organizationId, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}

		idx := findOrganization(results, organizationId)
		if idx == -1 {
			results = append(results, IdentityOrganization{
				OrganizationID: organizationId,
				Name:           name,
				Member:         true,
				Roles:          []string{},
			})
		} else {
			results[idx].Member = true
		}
	}

	// query for organizations for which the user has a role, or the user is a member of a team or group that has a role
	rows, err = db.Unscoped().Raw(`SELECT 
      i.id, 
      r.name,
      role.name
    FROM 
      identity_role ir, 
      resource r, 
      identities i,
      resource_type rt, role
		WHERE 
      ir.resource_id = r.resource_id
      and ir.resource_id = i.identity_resource_id
      and ir.role_id = role.role_id 
      and r.resource_type_id = rt.resource_type_id 
		  and rt.name = ? 
      and ir.deleted_at IS NULL
      and r.deleted_at IS NULL
      and rt.deleted_at IS NULL
      and role.deleted_at IS NULL
      and (ir.identity_id = ? 
      OR ir.identity_id in (
        WITH RECURSIVE m AS ( 
		      SELECT 
            member_id, 
            member_of 
          FROM 
            membership 
          WHERE 
            member_id = ? 
		      UNION SELECT 
            p.member_id, 
            p.member_of 
          FROM 
            membership p INNER JOIN m ON m.member_of = p.member_id
        )
		    select member_id from m
      ))`,
		IdentityResourceTypeOrganization, identityID, identityID).Rows()

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var id string
		var name string
		var roleName string
		rows.Scan(&id, &name, &roleName)
		organizationId, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}

		idx := findOrganization(results, organizationId)
		if idx == -1 {
			results = append(results, IdentityOrganization{
				OrganizationID: organizationId,
				Name:           name,
				Member:         false,
				Roles:          []string{roleName},
			})
		} else {
			found := false
			// Check if the role is already in the entry
			for _, r := range results[idx].Roles {
				if r == roleName {
					found = true
					break
				}
			}

			if !found {
				results[idx].Roles = append(results[idx].Roles, roleName)
			}

		}
	}

	return results, nil
}
