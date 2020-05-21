package main

import (
	"flag"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/tapirs/terraform-elb-to-alb/elbtoalb"
	"github.com/tapirs/terraform-elb-to-alb/elbtoalb-tools"
)

func main() {

	prePtr := flag.Bool("pre", false, "Run the pre stage")
  postPtr := flag.Bool("post", false, "Run the post stage")
	dirPtr := flag.String("tf_dir", "./", "Directory containing terraform files")

  flag.Parse()

  if *prePtr {
    fmt.Println("pre")
    elbtoalbtools.Pre(*dirPtr)
  } else if *postPtr {
    fmt.Println("post")
    elbtoalbtools.Post()
  } else {
		plugin.Serve(&plugin.ServeOpts{
			ProviderFunc: elbtoalb.Provider})
	}
}
