package main

import (
	"flag"
	"log"

	"github.com/Venafi/terraform-provider-venafi/venafi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	// remove date and time stamp from log output as the plugin SDK already adds its own
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	var debugMode bool

	flag.BoolVar(&debugMode, "debuggable", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	if debugMode {
		plugin.Serve(&plugin.ServeOpts{
			ProviderFunc: venafi.Provider,
			Debug:        true,
		})
	} else {
		plugin.Serve(&plugin.ServeOpts{
			ProviderFunc: venafi.Provider,
		})
	}
}
