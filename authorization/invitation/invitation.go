package invitation

import (
	uuid "github.com/satori/go.uuid"
)

type Invitation struct {
	IdentityID *uuid.UUID
	UserEmail  *string
	UserName   *string
	Member     bool
	Roles      []string
}
