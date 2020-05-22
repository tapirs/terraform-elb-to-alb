package elbtoalb

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceElbtoalbElbAttachment() *schema.Resource {
	return &schema.Resource{

		Schema: map[string]*schema.Schema{
			"elb": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},

			"instance": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},
		},
	}
}
