package errors

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/stretchr/testify/assert"
)

func TestSimpleError_Error(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	e := simpleError{message: "foo"}
	assert.Equal(t, "foo", e.Error())
}

func TestBadParameterError_Error(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	e := BadParameterError{parameter: "foo", value: "bar", errorMessage: "BadParamErrorMessage"}
	assert.Equal(t, fmt.Sprintf(stBadParameterErrorMsg, e.parameter, e.value, e.errorMessage), e.Error())

	e = BadParameterError{parameter: "foo", value: "bar", expectedValue: "foobar", hasExpectedValue: true, errorMessage: "BadParamErrorMessage"}
	assert.Equal(t, fmt.Sprintf(stBadParameterErrorExpectedMsg, e.parameter, e.value, e.expectedValue, e.errorMessage), e.Error())
}

func TestNotFoundError_Error(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	e := NotFoundError{entity: "foo", key: "id", value: "bar"}
	assert.Equal(t, fmt.Sprintf(stNotFoundErrorMsg, e.entity, e.key, e.value), e.Error())
}
