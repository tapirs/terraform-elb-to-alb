package elbtoalb

import (
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	// homedir "github.com/mitchellh/go-homedir"
)

func Provider() terraform.ResourceProvider {
	  log.Println("hello")
    provider := &schema.Provider{
			Schema: map[string]*schema.Schema{},

			ResourcesMap: map[string]*schema.Resource{
				"elbtoalb_elb":                         resourceElbtoalbElb(),
				"elbtoalb_elb_attachment":              resourceElbtoalbElbAttachment(),
				"elbtoalb_alb":                         resourceElbtoalbLb(),
				"elbtoalb_lb":                          resourceElbtoalbLb(),
				"elbtoalb_alb_listener":                resourceElbtoalbLbListener(),
				"elbtoalb_lb_listener":                 resourceElbtoalbLbListener(),
				"elbtoalb_alb_listener_certificate":    resourceElbtoalbLbListenerCertificate(),
				"elbtoalb_lb_listener_certificate":     resourceElbtoalbLbListenerCertificate(),
				"elbtoalb_alb_listener_rule":           resourceElbtoalbLbbListenerRule(),
				"elbtoalb_lb_listener_rule":            resourceElbtoalbLbbListenerRule(),
				"elbtoalb_alb_target_group":            resourceElbtoalbLbTargetGroup(),
				"elbtoalb_lb_target_group":             resourceElbtoalbLbTargetGroup(),
				"elbtoalb_alb_target_group_attachment": resourceElbtoalbLbTargetGroupAttachment(),
				"elbtoalb_lb_target_group_attachment":  resourceElbtoalbLbTargetGroupAttachment(),
			},
    }
		log.Println("completed provider")
		return provider
}
