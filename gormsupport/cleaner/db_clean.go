package cleaner

import (
	"database/sql"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

// DeleteCreatedEntities records all created entities on the gorm.DB connection
// and returns a function which can be called on defer to delete created
// entities in reverse order on function exit.
//
//
// Usage:
//
// func TestDatabaseActions(t *testing.T) {
//
// 	// setup database connection
// 	db := ....
// 	// setup auto clean up of created entities
// 	defer DeleteCreatedEntities(db)()
//
// 	repo := NewRepo(db)
// 	repo.Create(X)
// 	repo.Create(X)
// 	repo.Create(X)
// }
//
// Output:
//
// 2017/01/31 12:08:08 Deleting from x 6d143405-1232-40de-bc73-835b543cd972
// 2017/01/31 12:08:08 Deleting from x 0685068d-4934-4d9a-bac2-91eebbca9575
// 2017/01/31 12:08:08 Deleting from x 2d20944e-7952-40c1-bd15-f3fa1a70026d
func DeleteCreatedEntities(db *gorm.DB) func() {
	hookName := "mighti:record"
	type entity struct {
		table string
		keys  map[string]interface{}
	}
	var entities []entity
	hookRegistered := db.Callback().Create().Get(hookName) != nil
	if hookRegistered {
		hookName += "-" + uuid.NewV4().String()
	}
	db.Callback().Create().After("gorm:create").Register(hookName, func(scope *gorm.Scope) {
		fields := scope.PrimaryFields()
		keys := make(map[string]interface{})
		for _, field := range fields {
			keys[field.DBName] = field.Field.Interface()
		}
		log.Logger().Debugln(fmt.Sprintf("Inserted entities from %s with keys %v", scope.TableName(), keys))
		entities = append(entities, entity{table: scope.TableName(), keys: keys})
	})
	return func() {
		defer db.Callback().Create().Remove(hookName)
		// Find out if the current db object is already a transaction
		_, inTransaction := db.CommonDB().(*sql.Tx)
		tx := db
		if !inTransaction {
			tx = db.Begin()
		}
		for i := len(entities) - 1; i >= 0; i-- {
			entity := entities[i]
			log.Debug(nil, map[string]interface{}{
				"table":     entity.table,
				"keys":      entity.keys,
				"hook_name": hookName,
			}, "Deleting entities from '%s' table with keys %v", entity.table, entity.keys)
			if len(entity.keys) == 0 {
				log.Panic(nil, map[string]interface{}{
					"table":     entity.table,
					"hook_name": hookName,
				}, "no primary keys found!!!")
			}
			tx.Table(entity.table).Where(entity.keys).Delete("")
		}

		if !inTransaction {
			tx.Commit()
		}
	}
}
