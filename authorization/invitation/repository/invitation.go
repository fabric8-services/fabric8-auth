package repository

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"

	"fmt"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type Invitation struct {
	gormsupport.Lifecycle

	// This is the primary key value
	InvitationID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:invitation_id"`

	// The identity ID (organization, team or security group) to which the user is being invited to
	InviteTo *uuid.UUID `sql:"type:uuid" gorm:"column:invite_to"`

	// or, the Resource ID to which the user is being invited to accept a role
	ResourceID *string `sql:"type:string" gorm:"column:resource_id"`

	Identity   account.Identity `gorm:"ForeignKey:IdentityID;AssociationForeignKey:ID"`
	IdentityID uuid.UUID

	Member bool
}

func (m Invitation) TableName() string {
	return "invitation"
}

// GetLastModified returns the last modification time
func (m Invitation) GetLastModified() time.Time {
	return m.UpdatedAt
}

type InvitationRole struct {
	InvitationID uuid.UUID `sql:"type:uuid" gorm:"primary_key" gorm:"column:invitation_id"`

	Role   rolerepo.Role `gorm:"ForeignKey:RoleID;AssociationForeignKey:RoleID"`
	RoleID uuid.UUID     `sql:"type:uuid" gorm:"primary_key" gorm:"column:role_id"`
}

func (ir InvitationRole) TableName() string {
	return "invitation_role"
}

// GormInvitationRepository is the implementation of the storage interface for Invitation.
type GormInvitationRepository struct {
	db *gorm.DB
}

// NewInvitationRepository creates a new storage type.
func NewInvitationRepository(db *gorm.DB) InvitationRepository {
	return &GormInvitationRepository{db: db}
}

// InvitationRepository represents the storage interface.
type InvitationRepository interface {
	CheckExists(ctx context.Context, id uuid.UUID) (bool, error)
	Load(ctx context.Context, id uuid.UUID) (*Invitation, error)
	Create(ctx context.Context, i *Invitation) error
	Save(ctx context.Context, i *Invitation) error
	ListForIdentity(ctx context.Context, inviteToID uuid.UUID) ([]Invitation, error)
	ListForResource(ctx context.Context, resourceID string) ([]Invitation, error)
	Delete(ctx context.Context, id uuid.UUID) error

	ListRoles(ctx context.Context, id uuid.UUID) ([]rolerepo.Role, error)
	AddRole(ctx context.Context, invitationId uuid.UUID, roleId uuid.UUID) error
}

func (m *GormInvitationRepository) TableName() string {
	return "invitation"
}

func (m *GormInvitationRepository) CheckExists(ctx context.Context, id uuid.UUID) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				invitation_id=$1
				AND deleted_at IS NULL
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, id).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), id.String())
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

func (m *GormInvitationRepository) Load(ctx context.Context, id uuid.UUID) (*Invitation, error) {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "load"}, time.Now())
	var native Invitation
	err := m.db.Table(m.TableName()).Where("invitation_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("invitation", id.String())
	}
	return &native, errs.WithStack(err)
}

func (m *GormInvitationRepository) Create(ctx context.Context, i *Invitation) error {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "create"}, time.Now())
	if i.InvitationID == uuid.Nil {
		i.InvitationID = uuid.NewV4()
	}
	err := m.db.Debug().Create(i).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"invitation_id": i.InvitationID,
			"err":           err,
		}, "unable to create the invitation")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"invitation_id": i.InvitationID,
	}, "Invitation created!")
	return nil
}

func (m *GormInvitationRepository) Save(ctx context.Context, i *Invitation) error {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "save"}, time.Now())

	obj, err := m.Load(ctx, i.InvitationID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"invitation_id": i.InvitationID,
			"err":           err,
		}, "unable to update invitation")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(i).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"invitation_id": i.InvitationID,
	}, "Invitation saved!")
	return nil
}

func (m *GormInvitationRepository) ListForIdentity(ctx context.Context, inviteToID uuid.UUID) ([]Invitation, error) {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "listForGroup"}, time.Now())
	var rows []Invitation

	err := m.db.Model(&Invitation{}).Where("invite_to = ?", inviteToID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

func (m *GormInvitationRepository) ListForResource(ctx context.Context, resourceID string) ([]Invitation, error) {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "listForResource"}, time.Now())
	var rows []Invitation

	err := m.db.Model(&Invitation{}).Where("resource_to = ?", resourceID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

func (m *GormInvitationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "delete"}, time.Now())

	obj := Invitation{InvitationID: id}

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"invitation_id": id,
			"err":           err,
		}, "unable to delete the invitation")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"invitation_id": id,
	}, "Invitation deleted!")

	return nil
}

func (m *GormInvitationRepository) ListRoles(ctx context.Context, id uuid.UUID) ([]rolerepo.Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "list_roles"}, time.Now())

	var invitationRoles []InvitationRole

	err := m.db.Where("invitation_id = ?", id).Preload("Role").Find(&invitationRoles).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	results := make([]rolerepo.Role, len(invitationRoles))
	for index := 0; index < len(invitationRoles); index++ {
		results[index] = invitationRoles[index].Role
	}

	return results, nil

}

func (m *GormInvitationRepository) AddRole(ctx context.Context, invitationId uuid.UUID, roleId uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "invitation", "addrole"}, time.Now())
	invitationRole := &InvitationRole{
		InvitationID: invitationId,
		RoleID:       roleId,
	}

	err := m.db.Create(invitationRole).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"invitation_id": invitationId,
			"role_id":       roleId,
			"err":           err,
		}, "unable to create the invitation role")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"invitation_id": invitationId,
		"role_id":       roleId,
	}, "Invitation role created!")
	return nil
}
