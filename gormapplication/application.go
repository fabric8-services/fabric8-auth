package gormapplication

import (
	"fmt"
	"strconv"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/fabric8-services/fabric8-auth/token/provider"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// A TXIsoLevel specifies the characteristics of the transaction
// See https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
type TXIsoLevel int8

const (
	// TXIsoLevelDefault doesn't specify any transaction isolation level, instead the connection
	// based setting will be used.
	TXIsoLevelDefault TXIsoLevel = iota

	// TXIsoLevelReadCommitted means "A statement can only see rows committed before it began. This is the default."
	TXIsoLevelReadCommitted

	// TXIsoLevelRepeatableRead means "All statements of the current transaction can only see rows committed before the
	// first query or data-modification statement was executed in this transaction."
	TXIsoLevelRepeatableRead

	// TXIsoLevelSerializable means "All statements of the current transaction can only see rows committed
	// before the first query or data-modification statement was executed in this transaction.
	// If a pattern of reads and writes among concurrent serializable transactions would create a
	// situation which could not have occurred for any serial (one-at-a-time) execution of those
	// transactions, one of them will be rolled back with a serialization_failure error."
	TXIsoLevelSerializable
)

var x application.Application = &GormDB{}

var y application.Application = &GormTransaction{}

func NewGormDB(db *gorm.DB) *GormDB {
	return &GormDB{GormBase{db}, ""}
}

// GormBase is a base struct for gorm implementations of db & transaction
type GormBase struct {
	db *gorm.DB
}

type GormTransaction struct {
	GormBase
}

type GormDB struct {
	GormBase
	txIsoLevel string
}

func (g *GormBase) SpaceResources() space.ResourceRepository {
	return space.NewResourceRepository(g.db)
}

// Identities creates new Identity repository
func (g *GormBase) Identities() account.IdentityRepository {
	return account.NewIdentityRepository(g.db)
}

// Users creates new user repository
func (g *GormBase) Users() account.UserRepository {
	return account.NewUserRepository(g.db)
}

// OauthStates returns an oauth state reference repository
func (g *GormBase) OauthStates() auth.OauthStateReferenceRepository {
	return auth.NewOauthStateReferenceRepository(g.db)
}

// ExternalTokens returns an ExternalTokens repository
func (g *GormBase) ExternalTokens() provider.ExternalTokenRepository {
	return provider.NewExternalTokenRepository(g.db)
}

func (g *GormBase) DB() *gorm.DB {
	return g.db
}

// SetTransactionIsolationLevel sets the isolation level for
// See also https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
func (g *GormDB) SetTransactionIsolationLevel(level TXIsoLevel) error {
	switch level {
	case TXIsoLevelReadCommitted:
		g.txIsoLevel = "READ COMMITTED"
	case TXIsoLevelRepeatableRead:
		g.txIsoLevel = "REPEATABLE READ"
	case TXIsoLevelSerializable:
		g.txIsoLevel = "SERIALIZABLE"
	case TXIsoLevelDefault:
		g.txIsoLevel = ""
	default:
		return fmt.Errorf("Unknown transaction isolation level: " + strconv.FormatInt(int64(level), 10))
	}
	return nil
}

// Begin implements TransactionSupport
func (g *GormDB) BeginTransaction() (application.Transaction, error) {
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	if len(g.txIsoLevel) != 0 {
		tx := tx.Exec(fmt.Sprintf("set transaction isolation level %s", g.txIsoLevel))
		if tx.Error != nil {
			return nil, tx.Error
		}
		return &GormTransaction{GormBase{tx}}, nil
	}
	return &GormTransaction{GormBase{tx}}, nil
}

// Commit implements TransactionSupport
func (g *GormTransaction) Commit() error {
	err := g.db.Commit().Error
	g.db = nil
	return errors.WithStack(err)
}

// Rollback implements TransactionSupport
func (g *GormTransaction) Rollback() error {
	err := g.db.Rollback().Error
	g.db = nil
	return errors.WithStack(err)
}
