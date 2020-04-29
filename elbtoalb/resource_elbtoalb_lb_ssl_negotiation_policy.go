package elbtoalb

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceElbtoalbLBSSLNegotiationPolicy() *schema.Resource {
	return &schema.Resource{

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"load_balancer": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"lb_port": {
				Type:     schema.TypeInt,
				Required: true,
				ForceNew: true,
			},

			"attribute": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},

						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: func(v interface{}) int {
					var buf bytes.Buffer
					m := v.(map[string]interface{})
					buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
					return hashcode.String(buf.String())
				},
			},
		},
	}
}

// resourceElbtoalbLBSSLNegotiationPolicyParseId takes an ID and parses it into
// it's constituent parts. You need three axes (LB name, policy name, and LB
// port) to create or identify an SSL negotiation policy in AWS's API.
func resourceElbtoalbLBSSLNegotiationPolicyParseId(id string) (string, string, string) {
	parts := strings.SplitN(id, ":", 3)
	return parts[0], parts[1], parts[2]
}
