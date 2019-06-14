package rest

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/fabric8-services/fabric8-auth/errors"

	"context"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/client"
)

// Doer is a wrapper interface for goa client Doer
type HttpDoer interface {
	client.Doer
}

// HttpClient defines the Do method of the http client.
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type configuration interface {
	IsPostgresDeveloperModeEnabled() bool
}

// HttpClientDoer implements HttpDoer
type HttpClientDoer struct {
	HttpClient HttpClient
}

// DefaultHttpDoer creates a new HttpDoer with default http client
func DefaultHttpDoer() HttpDoer {
	return &HttpClientDoer{HttpClient: http.DefaultClient}
}

// Do overrides Do method of the default goa client Doer. It's needed for mocking http clients in tests.
func (d *HttpClientDoer) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return d.HttpClient.Do(req)
}

// Host returns the host from the given request if run in prod mode or if config is nil
// and "auth.openshift.io" if run in dev mode
func Host(req *goa.RequestData, config configuration) string {
	if config != nil && config.IsPostgresDeveloperModeEnabled() {
		return "auth.openshift.io"
	}
	return req.Host
}

// AbsoluteURL prefixes a relative URL with absolute address
// If config is not nil and run in dev mode then host is replaced by "auth.openshift.io"
func AbsoluteURL(req *goa.RequestData, relative string, config configuration) string {
	host := Host(req, config)
	return absoluteURLForHost(req, host, relative)
}

// ReplaceDomainPrefixInAbsoluteURL replaces the last name in the host of the URL by a new name.
// Example: https://api.service.domain.org -> https://sso.service.domain.org
// If replaceBy == "" then return trim the last name.
// Example: https://api.service.domain.org -> https://service.domain.org
// Also prefixes a relative URL with absolute address
// If config is not nil and run in dev mode then "auth.openshift.io" is used as a host
func ReplaceDomainPrefixInAbsoluteURL(req *goa.RequestData, replaceBy, relative string, config configuration) (string, error) {
	host := Host(req, config)
	if host == "" { // this happens for tests. See https://github.com/goadesign/goa/issues/1861
		return "", nil
	}
	newHost, err := ReplaceDomainPrefix(host, replaceBy)
	if err != nil {
		return "", err
	}
	return absoluteURLForHost(req, newHost, relative), nil
}

// ReplaceDomainPrefixInAbsoluteURLStr check ReplaceDomainPrefixInAbsoluteURL.  This works on url string.
func ReplaceDomainPrefixInAbsoluteURLStr(urlStr string, replaceBy, relative string) (string, error) {
	if urlStr == "" { // this happens for tests. See https://github.com/goadesign/goa/issues/1861
		return "", nil
	}
	url, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	newHost, err := ReplaceDomainPrefix(url.Host, replaceBy)
	if err != nil {
		return "", err
	}
	return toAbsoluteURL(url.Scheme, newHost, relative), nil
}

func absoluteURLForHost(req *goa.RequestData, host, relative string) string {
	scheme := "http"
	if req.URL != nil && req.URL.Scheme == "https" { // isHTTPS
		scheme = "https"
	}
	xForwardProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardProto != "" {
		scheme = xForwardProto
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, relative)
}

func toAbsoluteURL(scheme, host, relative string) string {
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, relative)
}

// ReplaceDomainPrefix replaces the last name in the host by a new name. Example: api.service.domain.org -> sso.service.domain.org
// If replaceBy == "" then return trim the last name. Example: api.service.domain.org -> service.domain.org
func ReplaceDomainPrefix(host string, replaceBy string) (string, error) {
	split := strings.SplitN(host, ".", 2)
	if len(split) < 2 {
		return host, errors.NewBadParameterError("host", host).Expected("must contain more at least one subdomain")
	}
	if replaceBy == "" {
		return split[1], nil
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
