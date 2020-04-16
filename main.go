package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/tapirs/terraform-elb-to-alb/elbtoalb"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: elbtoalb.Provider})
}
