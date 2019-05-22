package main

import (
	"github.com/terraform-providers/terraform-provider-venafi/venafi"
	"github.com/hashicorp/terraform/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: venafi.Provider,
	})
}
