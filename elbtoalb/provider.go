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

			ResourcesMap: map[string]*schema.Resource{
				"aws_elb":                         resourceAwsElb(),
				"aws_elb_attachment":              resourceAwsElbAttachment(),
				"aws_alb":                         resourceAwsLb(),
				"aws_lb":                          resourceAwsLb(),
				"aws_alb_listener":                resourceAwsLbListener(),
				"aws_lb_listener":                 resourceAwsLbListener(),
				"aws_alb_listener_certificate":    resourceAwsLbListenerCertificate(),
				"aws_lb_listener_certificate":     resourceAwsLbListenerCertificate(),
				"aws_alb_listener_rule":           resourceAwsLbbListenerRule(),
				"aws_lb_listener_rule":            resourceAwsLbbListenerRule(),
				"aws_alb_target_group":            resourceAwsLbTargetGroup(),
				"aws_lb_target_group":             resourceAwsLbTargetGroup(),
				"aws_alb_target_group_attachment": resourceAwsLbTargetGroupAttachment(),
				"aws_lb_target_group_attachment":  resourceAwsLbTargetGroupAttachment(),
			},
    }
}
