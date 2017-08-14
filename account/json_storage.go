package account

import (
	"database/sql/driver"
	"encoding/json"
	"reflect"

	"github.com/fabric8-services/fabric8-auth/convert"
	"github.com/pkg/errors"
)

type ContextInformation map[string]interface{}

// Ensure ContextInformation implements the Equaler interface
var _ convert.Equaler = ContextInformation{}
var _ convert.Equaler = (*ContextInformation)(nil)

// Equal returns true if two ContextInformation objects are equal; otherwise false is returned.
// TODO: (kwk) think about a better comparison for ContextInformation map.
func (f ContextInformation) Equal(u convert.Equaler) bool {
	other, ok := u.(ContextInformation)
	if !ok {
		return false
	}
	return reflect.DeepEqual(f, other)
}

func (j ContextInformation) Value() (driver.Value, error) {
	return toBytes(j)
}

func (j *ContextInformation) Scan(src interface{}) error {
	return fromBytes(src, j)
}

func toBytes(j interface{}) (driver.Value, error) {
	if j == nil {
		// log.Trace("returning null")
		return nil, nil
	}

	res, error := json.Marshal(j)
	return res, error
}

func fromBytes(src interface{}, target interface{}) error {
	if src == nil {
		target = nil
		return nil
	}
	s, ok := src.([]byte)
	if !ok {
		return errors.New("Scan source was not string")
	}
	return json.Unmarshal(s, target)
}
