package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/opencredo/terraform-provider-venafi/venafi"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: venafi.Provider,
	})
}
