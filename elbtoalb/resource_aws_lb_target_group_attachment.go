package elbtoalb

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAwsLbTargetGroupAttachment() *schema.Resource {
	return &schema.Resource{

		Schema: map[string]*schema.Schema{
			"target_group_arn": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},

			"target_id": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},

			"port": {
				Type:     schema.TypeInt,
				ForceNew: true,
				Optional: true,
			},

			"availability_zone": {
				Type:     schema.TypeString,
				ForceNew: true,
				Optional: true,
			},
		},
	}
}
