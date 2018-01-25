package controller_test

import (
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/log"
)

// getHeader a utility function to retrieve the (first) value of a response header given its name.
func getHeader(res http.ResponseWriter, headerName string) (*string, error) {
	values := res.Header()[headerName]
	if len(values) == 0 {
		return nil, fmt.Errorf("No '%s' header was found in the response", values)
	}
	value := values[0]
	log.Debug(nil, map[string]interface{}{headerName: value}, "retrieved response header")
	return &value, nil
}
