package rest

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/fabric8-services/fabric8-auth/errors"

	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/goadesign/goa"
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

// ValidateEmail return true if the string is a valid email address
// This is a very simple validation. It just checks if there is @ and dot in the address
func ValidateEmail(email string) (bool, error) {
	// .+@.+\..+
	return regexp.MatchString(".+@.+\\..+", email)
}

// AddParam adds a parameter to URL
func AddParam(urlString string, paramName string, paramValue string) (string, error) {
	return AddParams(urlString, map[string]string{paramName: paramValue})
}

// AddParams adds parameters to URL
func AddParams(urlString string, params map[string]string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	parameters := parsedURL.Query()
	for k, v := range params {
		parameters.Add(k, v)
	}
	parsedURL.RawQuery = parameters.Encode()

	return parsedURL.String(), nil
}

// AddTrailingSlashToURL adds a trailing slash to the URL if it doesn't have it already
// If URL is an empty string the function returns an empty string too
func AddTrailingSlashToURL(url string) string {
	if url != "" && !strings.HasSuffix(url, "/") {
		return url + "/"
	}
	return url
}
