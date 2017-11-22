package rest

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/fabric8-services/fabric8-auth/errors"

	"github.com/goadesign/goa"
	"io/ioutil"
	"net/http"
)

// AbsoluteURL prefixes a relative URL with absolute address
func AbsoluteURL(req *goa.RequestData, relative string) string {
	scheme := "http"
	if req.URL != nil && req.URL.Scheme == "https" { // isHTTPS
		scheme = "https"
	}
	xForwardProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardProto != "" {
		scheme = xForwardProto
	}
	return fmt.Sprintf("%s://%s%s", scheme, req.Host, relative)
}

// ReplaceDomainPrefix replaces the last name in the host by a new name. Example: api.service.domain.org -> sso.service.domain.org
func ReplaceDomainPrefix(host string, replaceBy string) (string, error) {
	split := strings.SplitN(host, ".", 2)
	if len(split) < 2 {
		return host, errors.NewBadParameterError("host", host).Expected("must contain more than one domain")
	}
	return replaceBy + "." + split[1], nil
}

// ReadBody reads body from a ReadCloser and returns it as a string
func ReadBody(body io.ReadCloser) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(body)
	return buf.String()
}

// CloseResponse reads the body and close the response. To be used to prevent file descriptor leaks.
func CloseResponse(response *http.Response) {
	ioutil.ReadAll(response.Body)
	response.Body.Close()
}
