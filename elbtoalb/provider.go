package elbtoalb

import (
	// "log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	// homedir "github.com/mitchellh/go-homedir"
)

func Provider() terraform.ResourceProvider {
    return &schema.Provider{
			Schema: map[string]*schema.Schema{},

			ResourcesMap: map[string]*schema.Resource{},
    }
}
