package main

import (
	"flag"
	"log"

	"github.com/Venafi/terraform-provider-venafi/venafi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

const providerAddress = "registry.terraform.io/Venafi/venafi"

func main() {
	// remove date and time stamp from log output as the plugin SDK already adds its own
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		ProviderFunc: venafi.Provider,
		Debug:        debugMode,
		ProviderAddr: providerAddress,
	}

	plugin.Serve(opts)
}
