package venafi

import (
	"github.com/Venafi/govcert"
	vcert "github.com/Venafi/govcert/embedded"
)

type Config struct {
	APIKey string
	URL string
	Username string
	Password string
	Zone   string
}

type VenafiClient struct {
	client govcert.Client
	zone   string
	apikey string
	url string
	tppuser string
	tpppass string
}

func (c Config) Client() *VenafiClient {
	if len(c.Username) > 0 {
		return &VenafiClient{
			client: vcert.NewClientTPP(c.Username,c.Password,c.URL),
			zone:   c.Zone,
			url: c.URL,
			tppuser: c.Username,
			tpppass: c.Password,
		}
	} else {
		return &VenafiClient{
			client: vcert.NewClient(c.APIKey,c.URL),
			zone:   c.Zone,
			apikey: c.APIKey,
			url:	c.URL,
		}
	}
}
