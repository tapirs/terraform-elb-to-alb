package elbtoalb

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceElbtoalbLbListenerCertificate() *schema.Resource {
	return &schema.Resource{

		Schema: map[string]*schema.Schema{
			"listener_arn": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"certificate_arn": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
		},
	}
}
