package repository

import (
	"github.com/fabric8-services/fabric8-auth/convert"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"context"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

const (
	oauthStateTableName = "oauth_state_references"
)

// OauthStateReference represents a oauth state reference
type OauthStateReference struct {
	gormsupport.Lifecycle
	ID           uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"`
	State        string
	Referrer     string
	ResponseMode *string
}

// TableName implements gorm.tabler
func (r OauthStateReference) TableName() string {
	return oauthStateTableName
}

// Equal returns true if two States objects are equal; otherwise false is returned.
func (r OauthStateReference) Equal(u convert.Equaler) bool {
	other, ok := u.(OauthStateReference)
	if !ok {
		return false
	}
	if r.ID != other.ID {
		return false
	}
	if r.State != other.State {
		return false
	}
	if r.Referrer != other.Referrer {
		return false
	}

	if r.ResponseMode == nil {
		if other.ResponseMode != nil {
			return false
		}
	} else {
		if other.ResponseMode == nil {
			return false
		} else if *r.ResponseMode != *other.ResponseMode {
			return false
		}
	}
	return true
}

// OauthStateReferenceRepository encapsulate storage & retrieval of state references
type OauthStateReferenceRepository interface {
	Create(ctx context.Context, state *OauthStateReference) (*OauthStateReference, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	Cleanup(ctx context.Context) (int64, error)
	Load(ctx context.Context, state string) (*OauthStateReference, error)
}

// NewOauthStateReferenceRepository creates a new oauth state reference repo
func NewOauthStateReferenceRepository(db *gorm.DB) *GormOauthStateReferenceRepository {
	return &GormOauthStateReferenceRepository{db}
}

// GormOauthStateReferenceRepository implements OauthStateReferenceRepository using gorm
type GormOauthStateReferenceRepository struct {
	db *gorm.DB
}

// Delete deletes the reference with the given id
// returns NotFoundError or InternalError
func (r *GormOauthStateReferenceRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	if ID == uuid.Nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_state_reference_id": ID.String(),
		}, "unable to find the oauth state reference by ID")
		return errors.NewNotFoundError("oauth state reference", ID.String())
	}
	reference := OauthStateReference{ID: ID}
	tx := r.db.Delete(reference)

	if err := tx.Error; err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_state_reference_id": ID.String(),
		}, "unable to delete the oauth state reference")
		return errors.NewInternalError(err)
	}
	if tx.RowsAffected == 0 {
		log.Error(ctx, map[string]interface{}{
			"oauth state reference": ID.String(),
		}, "none row was affected by the deletion operation")
		return errors.NewNotFoundError("oauth state reference", ID.String())
	}

	return nil
}

// Cleanup deletes all oauth references created more than 24hrs ago
// returns NotFoundError or InternalError
func (r *GormOauthStateReferenceRepository) Cleanup(ctx context.Context) (int64, error) {
	result := r.db.Exec(`delete from oauth_state_references 
		where id in (
			select id from oauth_state_references 
			where created_at < current_timestamp - interval '1 day' limit 1000)`)
	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"error": result.Error.Error(),
		}, "unable to cleanup oauth state references")
		return -1, errors.NewInternalError(result.Error)
	}
	log.Info(ctx, map[string]interface{}{
		"count": result.RowsAffected,
	}, "cleanup chunk of old oauth state references")
	return result.RowsAffected, nil
}

// Create creates a new oauth state reference in the DB
// returns InternalError
func (r *GormOauthStateReferenceRepository) Create(ctx context.Context, reference *OauthStateReference) (*OauthStateReference, error) {
	if reference.ID == uuid.Nil {
		reference.ID = uuid.NewV4()
	}

	tx := r.db.Create(reference)
	if err := tx.Error; err != nil {
		return nil, errors.NewInternalError(err)
	}

	log.Info(ctx, map[string]interface{}{
		"oauth_state_reference_id": reference.ID,
	}, "Oauth state reference created successfully")
	return reference, nil
}

// Load loads state reference by state
func (r *GormOauthStateReferenceRepository) Load(ctx context.Context, state string) (*OauthStateReference, error) {

	ref := OauthStateReference{}

	tx := r.db.Where("state=?", state).First(&ref)
	if tx.RecordNotFound() {
		log.Error(ctx, map[string]interface{}{
			"state": state,
		}, "Could not find oauth state reference by state")
		return nil, errors.NewNotFoundErrorWithKey("oauth_state_references", "state", state)
	}
	if tx.Error != nil {
		return nil, errors.NewInternalError(tx.Error)
	}
	return &ref, nil
}
