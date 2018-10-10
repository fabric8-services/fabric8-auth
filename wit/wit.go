package wit

import "github.com/goadesign/goa/uuid"

type Configuration interface {
	GetWITURL() (string, error)
}

type Space struct {
	ID          uuid.UUID
	OwnerID     uuid.UUID
	Name        string
	Description string
}
