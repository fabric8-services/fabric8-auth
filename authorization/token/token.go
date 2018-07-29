package token

import "github.com/satori/go.uuid"

// RPTTokenState is a DTO used to pass token state between the service and controller layer
type RPTTokenState struct {
	TokenID   uuid.UUID
	Resources []RPTTokenResource
}

// RPTTokenResource represents a single resource (plus its scopes) inside an RPT token
type RPTTokenResource struct {
	ResourceID string
	Scopes     []string
}
