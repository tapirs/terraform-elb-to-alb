package elbtoalb

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/tapirs/terraform-elb-to-alb/elbtoalb/internal/keyvaluetags"
)

func resourceAwsElb() *schema.Resource {
	return &schema.Resource{
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name_prefix"},
				ValidateFunc:  validateElbName,
			},
			"name_prefix": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name"},
				ValidateFunc:  validateElbNamePrefix,
			},

			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"internal": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"cross_zone_load_balancing": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			"availability_zones": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Set:      schema.HashString,
			},

			"instances": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Set:      schema.HashString,
			},

			"security_groups": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Set:      schema.HashString,
			},

			"source_security_group": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"source_security_group_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"subnets": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Set:      schema.HashString,
			},

			"idle_timeout": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      60,
				ValidateFunc: validation.IntBetween(1, 4000),
			},

			"connection_draining": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			"connection_draining_timeout": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  300,
			},

			"access_logs": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"interval": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      60,
							ValidateFunc: validateAccessLogsInterval,
						},
						"bucket": {
							Type:     schema.TypeString,
							Required: true,
						},
						"bucket_prefix": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},
					},
				},
			},

			"listener": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"instance_port": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						"instance_protocol": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateListenerProtocol(),
						},

						"lb_port": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						"lb_protocol": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateListenerProtocol(),
						},

						"ssl_certificate_id": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateArn,
						},
					},
				},
				Set: resourceAwsElbListenerHash,
			},

			"health_check": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"healthy_threshold": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(2, 10),
						},

						"unhealthy_threshold": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(2, 10),
						},

						"target": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateHeathCheckTarget,
						},

						"interval": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(5, 300),
						},

						"timeout": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(2, 60),
						},
					},
				},
			},

			"dns_name": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"zone_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchema(),
		},
	}
}

// flattenAwsELbResource takes a *elbv2.LoadBalancer and populates all respective resource fields.
func flattenAwsELbResource(d *schema.ResourceData, ec2conn *ec2.EC2, elbconn *elb.ELB, lb *elb.LoadBalancerDescription) error {
	describeAttrsOpts := &elb.DescribeLoadBalancerAttributesInput{
		LoadBalancerName: aws.String(d.Id()),
	}
	describeAttrsResp, err := elbconn.DescribeLoadBalancerAttributes(describeAttrsOpts)
	if err != nil {
		return fmt.Errorf("Error retrieving ELB: %s", err)
	}

	lbAttrs := describeAttrsResp.LoadBalancerAttributes

	d.Set("name", lb.LoadBalancerName)
	d.Set("dns_name", lb.DNSName)
	d.Set("zone_id", lb.CanonicalHostedZoneNameID)

	var scheme bool
	if lb.Scheme != nil {
		scheme = *lb.Scheme == "internal"
	}
	d.Set("internal", scheme)
	d.Set("availability_zones", flattenStringList(lb.AvailabilityZones))
	d.Set("instances", flattenInstances(lb.Instances))
	d.Set("listener", flattenListeners(lb.ListenerDescriptions))
	d.Set("security_groups", flattenStringList(lb.SecurityGroups))
	// if lb.SourceSecurityGroup != nil {
	// 	group := lb.SourceSecurityGroup.GroupName
	// 	if lb.SourceSecurityGroup.OwnerAlias != nil && *lb.SourceSecurityGroup.OwnerAlias != "" {
	// 		group = aws.String(*lb.SourceSecurityGroup.OwnerAlias + "/" + *lb.SourceSecurityGroup.GroupName)
	// 	}
	// 	d.Set("source_security_group", group)
	//
	// 	// Manually look up the ELB Security Group ID, since it's not provided
	// 	var elbVpc string
	// 	if lb.VPCId != nil {
	// 		elbVpc = *lb.VPCId
	// 		sgId, err := sourceSGIdByName(ec2conn, *lb.SourceSecurityGroup.GroupName, elbVpc)
	// 		if err != nil {
	// 			return fmt.Errorf("Error looking up ELB Security Group ID: %s", err)
	// 		} else {
	// 			d.Set("source_security_group_id", sgId)
	// 		}
	// 	}
	// }
	d.Set("subnets", flattenStringList(lb.Subnets))
	if lbAttrs.ConnectionSettings != nil {
		d.Set("idle_timeout", lbAttrs.ConnectionSettings.IdleTimeout)
	}
	d.Set("connection_draining", lbAttrs.ConnectionDraining.Enabled)
	d.Set("connection_draining_timeout", lbAttrs.ConnectionDraining.Timeout)
	d.Set("cross_zone_load_balancing", lbAttrs.CrossZoneLoadBalancing.Enabled)
	if lbAttrs.AccessLog != nil {
		// The AWS API does not allow users to remove access_logs, only disable them.
		// During creation of the ELB, Terraform sets the access_logs to disabled,
		// so there should not be a case where lbAttrs.AccessLog above is nil.

		// Here we do not record the remove value of access_log if:
		// - there is no access_log block in the configuration
		// - the remote access_logs are disabled
		//
		// This indicates there is no access_log in the configuration.
		// - externally added access_logs will be enabled, so we'll detect the drift
		// - locally added access_logs will be in the config, so we'll add to the
		// API/state
		// See https://github.com/hashicorp/terraform/issues/10138
		_, n := d.GetChange("access_logs")
		elbal := lbAttrs.AccessLog
		nl := n.([]interface{})
		if len(nl) == 0 && !*elbal.Enabled {
			elbal = nil
		}
		if err := d.Set("access_logs", flattenAccessLog(elbal)); err != nil {
			return err
		}
	}

	tags, err := keyvaluetags.ElbListTags(elbconn, d.Id())

	if err != nil {
		return fmt.Errorf("error listing tags for ELB (%s): %s", d.Id(), err)
	}

	if err := d.Set("tags", tags.IgnoreAws().Map()); err != nil {
		return fmt.Errorf("error setting tags: %s", err)
	}

	// There's only one health check, so save that to state as we
	// currently can
	if *lb.HealthCheck.Target != "" {
		d.Set("health_check", flattenHealthCheck(lb.HealthCheck))
	}

	return nil
}

func resourceAwsElbListenerHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["instance_port"].(int)))
	buf.WriteString(fmt.Sprintf("%s-",
		strings.ToLower(m["instance_protocol"].(string))))
	buf.WriteString(fmt.Sprintf("%d-", m["lb_port"].(int)))
	buf.WriteString(fmt.Sprintf("%s-",
		strings.ToLower(m["lb_protocol"].(string))))

	if v, ok := m["ssl_certificate_id"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	return hashcode.String(buf.String())
}

func isLoadBalancerNotFound(err error) bool {
	elberr, ok := err.(awserr.Error)
	return ok && elberr.Code() == elb.ErrCodeAccessPointNotFoundException
}

func validateAccessLogsInterval(v interface{}, k string) (ws []string, errors []error) {
	value := v.(int)

	// Check if the value is either 5 or 60 (minutes).
	if value != 5 && value != 60 {
		errors = append(errors, fmt.Errorf(
			"%q contains an invalid Access Logs interval \"%d\". "+
				"Valid intervals are either 5 or 60 (minutes).",
			k, value))
	}
	return
}

func validateHeathCheckTarget(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	// Parse the Health Check target value.
	matches := regexp.MustCompile(`\A(\w+):(\d+)(.+)?\z`).FindStringSubmatch(value)

	// Check if the value contains a valid target.
	if matches == nil || len(matches) < 1 {
		errors = append(errors, fmt.Errorf(
			"%q contains an invalid Health Check: %s",
			k, value))

		// Invalid target? Return immediately,
		// there is no need to collect other
		// errors.
		return
	}

	// Check if the value contains a valid protocol.
	if !isValidProtocol(matches[1]) {
		errors = append(errors, fmt.Errorf(
			"%q contains an invalid Health Check protocol %q. "+
				"Valid protocols are either %q, %q, %q, or %q.",
			k, matches[1], "TCP", "SSL", "HTTP", "HTTPS"))
	}

	// Check if the value contains a valid port range.
	port, _ := strconv.Atoi(matches[2])
	if port < 1 || port > 65535 {
		errors = append(errors, fmt.Errorf(
			"%q contains an invalid Health Check target port \"%d\". "+
				"Valid port is in the range from 1 to 65535 inclusive.",
			k, port))
	}

	switch strings.ToLower(matches[1]) {
	case "tcp", "ssl":
		// Check if value is in the form <PROTOCOL>:<PORT> for TCP and/or SSL.
		if matches[3] != "" {
			errors = append(errors, fmt.Errorf(
				"%q cannot contain a path in the Health Check target: %s",
				k, value))
		}

	case "http", "https":
		// Check if value is in the form <PROTOCOL>:<PORT>/<PATH> for HTTP and/or HTTPS.
		if matches[3] == "" {
			errors = append(errors, fmt.Errorf(
				"%q must contain a path in the Health Check target: %s",
				k, value))
		}

		// Cannot be longer than 1024 multibyte characters.
		if len([]rune(matches[3])) > 1024 {
			errors = append(errors, fmt.Errorf("%q cannot contain a path longer "+
				"than 1024 characters in the Health Check target: %s",
				k, value))
		}

	}

	return
}

func isValidProtocol(s string) bool {
	if s == "" {
		return false
	}
	s = strings.ToLower(s)

	validProtocols := map[string]bool{
		"http":  true,
		"https": true,
		"ssl":   true,
		"tcp":   true,
	}

	if _, ok := validProtocols[s]; !ok {
		return false
	}

	return true
}

func validateListenerProtocol() schema.SchemaValidateFunc {
	return validation.StringInSlice([]string{
		"HTTP",
		"HTTPS",
		"SSL",
		"TCP",
	}, true)
}
