package http

import (
	"net/http"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/docker/verify-docker-cli-plugin/internal/version"
)

type userAgentTransporter struct {
	ua string
	rt http.RoundTripper
}

type Option = func(*http.Client)

func (u *userAgentTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", u.ua)

	return u.rt.RoundTrip(req)
}

func Transport() http.RoundTripper {
	return &userAgentTransporter{
		ua: version.UserAgent(),
		rt: cleanhttp.DefaultTransport(),
	}
}
