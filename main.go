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
		err := elbtoalbtools.Pre(*dirPtr)
		if err != nil {
			fmt.Println(err)
		}
	} else if *postPtr {
		fmt.Println("post")
		err := elbtoalbtools.Post()
		if err != nil {
			fmt.Println(err)
		}
	} else {
		plugin.Serve(&plugin.ServeOpts{
			ProviderFunc: elbtoalb.Provider})
	}
}
