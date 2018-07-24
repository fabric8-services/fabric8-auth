package wit

import "github.com/goadesign/goa/uuid"

type Configuration interface {
	GetWITURL() (string, error)
}

type Space struct {
	ID          uuid.UUID
	Name        string
	Description string
	OwnerID     uuid.UUID
}
