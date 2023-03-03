package cas

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	gocas "gopkg.in/cas.v2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds configuration options for cas logins.
type Config struct {
	Server             string `json:"server"`
	RedirectURI        string `json:"redirectURI"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}

func (c Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	casURL, err := url.Parse(c.Server)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(c.RedirectURI)
	if err != nil {
		return nil, err
	}

	return &casConnector{
		Config:     c,
		pathSuffix: "/cas",
		client: gocas.NewRestClient(&gocas.RestOptions{
			CasURL:     casURL,
			ServiceURL: redirectURL,
			Client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
				},
			},
			URLScheme: nil,
		}),
	}, nil
}

var (
	_ connector.CallbackConnector = (*casConnector)(nil)
	_ connector.RefreshConnector  = (*casConnector)(nil)
)

type casConnector struct {
	Config
	pathSuffix string
	client     *gocas.RestClient
}

func (c *casConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	//TODO implement me
	panic("implement me")
}

func (c *casConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.RedirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.RedirectURI)
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}

	server, err := url.Parse(c.Server)
	if err != nil {
		return "", fmt.Errorf("failed to parse server %q: %v", c.Server, err)
	}

	v := u.Query()
	v.Set("state", state)

	u.RawQuery = v.Encode()
	service := u.String()
	v.Set("service", service)
	server.RawQuery = v.Encode()

	return server.String(), nil
}

func (c *casConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	// CAS callback, see also https://apereo.github.io/cas/6.3.x/protocol/CAS-Protocol-V2-Specification.html#25-servicevalidate-cas-20
	ticket := r.URL.Query().Get("ticket")
	resp, err := c.client.ValidateServiceTicket(gocas.ServiceTicket(ticket))
	if err != nil {
		return identity, fmt.Errorf("cas: failed to validate service ticket : %s", err)
	}

	return connector.Identity{
		UserID:            resp.User,
		Username:          resp.User,
		PreferredUsername: resp.User,
	}, nil
}
