package venafi

import (
	"github.com/Venafi/govcert"
	vcert "github.com/Venafi/govcert/embedded"
)

type Config struct {
	APIKey string
	Zone   string
}

type VenafiClient struct {
	client govcert.Client
	zone   string
	apikey string
}

func (c Config) Client() *VenafiClient {
	return &VenafiClient{
		client: vcert.NewClient(c.APIKey),
		zone:   c.Zone,
		apikey: c.APIKey,
	}
}
