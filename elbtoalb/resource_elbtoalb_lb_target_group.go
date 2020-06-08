package elbtoalb

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

type Healthcheck struct {
	Enabled bool
	Interval  int
	Path  string
	Port string
	Protocol string
	Timeout int
	Healthy_threshold int
	Unhealthy_threshold int
	Matcher string
}

func resourceElbtoalbLbTargetGroup() *schema.Resource {
	return &schema.Resource{
		// NLBs have restrictions on them at this time
		CustomizeDiff: resourceElbtoalbLbTargetGroupCustomizeDiff,
		Create:        resourceElbtoalbLbTargetGroupCreate,
		Read:          resourceElbtoalbLbTargetGroupRead,
		Delete:        resourceElbtoalbLbTargetGroupDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"arn_suffix": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"name": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name_prefix"},
				ValidateFunc:  validateLbTargetGroupName,
			},
			"name_prefix": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name"},
				ValidateFunc:  validateLbTargetGroupNamePrefix,
			},

			"port": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			"protocol": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					elbv2.ProtocolEnumHttp,
					elbv2.ProtocolEnumHttps,
					elbv2.ProtocolEnumTcp,
					elbv2.ProtocolEnumTls,
					elbv2.ProtocolEnumUdp,
					elbv2.ProtocolEnumTcpUdp,
				}, true),
			},

			"vpc_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"deregistration_delay": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				Default:      300,
				ValidateFunc: validation.IntBetween(0, 3600),
			},

			"slow_start": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				Default:      0,
				ValidateFunc: validateSlowStart,
			},

			"proxy_protocol_v2": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"lambda_multi_value_headers_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"target_type": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  elbv2.TargetTypeEnumInstance,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					elbv2.TargetTypeEnumInstance,
					elbv2.TargetTypeEnumIp,
					elbv2.TargetTypeEnumLambda,
				}, false),
			},

			"load_balancing_algorithm_type": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"round_robin",
					"least_outstanding_requests",
				}, false),
			},

			"stickiness": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								"lb_cookie",
							}, false),
						},
						"cookie_duration": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      86400,
							ValidateFunc: validation.IntBetween(0, 604800),
						},
					},
				},
			},

			"health_check": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},

						"interval": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  30,
						},

						"path": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validateAwsLbTargetGroupHealthCheckPath,
						},

						"port": {
							Type:             schema.TypeString,
							Optional:         true,
							Default:          "traffic-port",
							ValidateFunc:     validateAwsLbTargetGroupHealthCheckPort,
							DiffSuppressFunc: suppressIfTargetType(elbv2.TargetTypeEnumLambda),
						},

						"protocol": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  elbv2.ProtocolEnumHttp,
							StateFunc: func(v interface{}) string {
								return strings.ToUpper(v.(string))
							},
							ValidateFunc: validation.StringInSlice([]string{
								elbv2.ProtocolEnumHttp,
								elbv2.ProtocolEnumHttps,
								elbv2.ProtocolEnumTcp,
							}, true),
							DiffSuppressFunc: suppressIfTargetType(elbv2.TargetTypeEnumLambda),
						},

						"timeout": {
							Type:         schema.TypeInt,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validation.IntBetween(2, 120),
						},

						"healthy_threshold": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      3,
							ValidateFunc: validation.IntBetween(2, 10),
						},

						"matcher": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},

						"unhealthy_threshold": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      3,
							ValidateFunc: validation.IntBetween(2, 10),
						},
					},
				},
			},

			// "tags": tagsSchemaForceNew(),
		},
	}
}

func resourceElbtoalbLbTargetGroupCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("in lb target group create")

	// Expand the "listener" set to aws-sdk-go compat []*elb.Listener
	listeners, err := expandListeners(d.Get("listener").(*schema.Set).List())
	if err != nil {
		return err
	}

	deregistrationDelay := d.Get("connection_draining_timeout")

	healthcheck_list := d.Get("health_check").([]interface{})
	var healthcheck Healthcheck
	if len(healthcheck_list) > 0 {
		healthcheck_map := healthcheck_list[0].(map[string]interface{})
		healthcheck.Enabled = true
		healthcheck.Matcher = "200"
		healthcheck.Healthy_threshold = healthcheck_map["healthy_threshold"].(int)
		healthcheck.Unhealthy_threshold = healthcheck_map["unhealthy_threshold"].(int)
		healthcheck.Interval = healthcheck_map["interval"].(int)
		healthcheck.Timeout = healthcheck_map["timeout"].(int)
		healthcheck.Protocol = "HTTP"
		healthcheck.Port = "traffic_port"
		healthcheck.Path = "/"

		re, err := regexp.Compile(`(?s)(.*):(\d+)(/.*)`)
		if err != nil {
			log.Println(err)
			return err
		}

		target := re.FindStringSubmatch(healthcheck_map["target"].(string))
		if len(target) == 3 {
			healthcheck.Protocol = target[0]
			healthcheck.Port = target[1]
			healthcheck.Path = target[2]
		}
	}

	for _, listener := range listeners {
		log.Println(listener)

		instancePort := *listener.InstancePort
		instanceProtocol := "HTTP"

		if (strings.ToUpper(*listener.InstanceProtocol) == elbv2.ProtocolEnumHttps || strings.ToUpper(*listener.InstanceProtocol) == elbv2.ProtocolEnumTls) && *listener.SSLCertificateId != "" {
			instanceProtocol = "HTTPS"
		}

		var groupName string
		if v, ok := d.GetOk("name"); ok {
			groupName = strings.Replace(v.(string), "elb-", "tg-", 1) + "-" + strconv.FormatInt(instancePort, 10)
		} else if v, ok := d.GetOk("name_prefix"); ok {
			groupName = resource.PrefixedUniqueId(v.(string))
		} else {
			groupName = resource.PrefixedUniqueId("tf-")
		}

		resourceName := strings.ReplaceAll(groupName, "-e2a-env-br", "")

		err = os.MkdirAll("./lb_terraform/target_group", 0755)
		if err != nil {
			return err
		}

		f, err := os.Create(fmt.Sprintf("./lb_terraform/target_group/%s.tf", resourceName))
		if err != nil {
			return err
		}

		defer f.Close()

		w := bufio.NewWriter(f)
		_, err = w.WriteString(fmt.Sprintf("resource \"aws_lb_target_group\" \"%s\" {\nname = \"%s\"\nport = %d\nprotocol = \"%s\"\nvpc_id = vpc-id\n\nderegistration_delay = %d\n\nhealth_check {\nenabled = %v\ninterval = %d\npath = \"%s\"\nport = \"%s\"\nprotocol = \"%s\"\ntimeout = %d\nhealthy_threshold = %d\nunhealthy_threshold = %d\nmatcher = \"%s\"\n}\n}", groupName, groupName, instancePort, instanceProtocol, deregistrationDelay, healthcheck.Enabled, healthcheck.Interval, healthcheck.Path, healthcheck.Port, healthcheck.Protocol, healthcheck.Timeout, healthcheck.Healthy_threshold, healthcheck.Unhealthy_threshold, healthcheck.Matcher))
		if err != nil {
			return err
		}

		w.Flush()
	}

	return nil
}

func resourceElbtoalbLbTargetGroupRead(d *schema.ResourceData, meta interface{}) error {
	log.Println("in read")

	return nil
}

func resourceElbtoalbLbTargetGroupDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("in delete")

	return nil
}

func suppressIfTargetType(t string) schema.SchemaDiffSuppressFunc {
	return func(k string, old string, new string, d *schema.ResourceData) bool {
		return d.Get("target_type").(string) == t
	}
}

func validateAwsLbTargetGroupHealthCheckPath(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if len(value) > 1024 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 1024 characters: %q", k, value))
	}
	if len(value) > 0 && !strings.HasPrefix(value, "/") {
		errors = append(errors, fmt.Errorf(
			"%q must begin with a '/' character: %q", k, value))
	}
	return
}

func validateSlowStart(v interface{}, k string) (ws []string, errors []error) {
	value := v.(int)

	// Check if the value is between 30-900 or 0 (seconds).
	if value != 0 && !(value >= 30 && value <= 900) {
		errors = append(errors, fmt.Errorf(
			"%q contains an invalid Slow Start Duration \"%d\". "+
				"Valid intervals are 30-900 or 0 to disable.",
			k, value))
	}
	return
}

func validateAwsLbTargetGroupHealthCheckPort(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if value == "traffic-port" {
		return
	}

	port, err := strconv.Atoi(value)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q must be a valid port number (1-65536) or %q", k, "traffic-port"))
	}

	if port < 1 || port > 65536 {
		errors = append(errors, fmt.Errorf("%q must be a valid port number (1-65536) or %q", k, "traffic-port"))
	}

	return
}

func lbTargetGroupSuffixFromARN(arn *string) string {
	if arn == nil {
		return ""
	}

	if arnComponents := regexp.MustCompile(`arn:.*:targetgroup/(.*)`).FindAllStringSubmatch(*arn, -1); len(arnComponents) == 1 {
		if len(arnComponents[0]) == 2 {
			return fmt.Sprintf("targetgroup/%s", arnComponents[0][1])
		}
	}

	return ""
}

func resourceElbtoalbLbTargetGroupCustomizeDiff(diff *schema.ResourceDiff, v interface{}) error {
	protocol := diff.Get("protocol").(string)
	if protocol == elbv2.ProtocolEnumTcp {
		// TCP load balancers do not support stickiness
		if stickinessBlocks := diff.Get("stickiness").([]interface{}); len(stickinessBlocks) == 1 {
			stickiness := stickinessBlocks[0].(map[string]interface{})
			if val := stickiness["enabled"].(bool); val {
				return fmt.Errorf("Network Load Balancers do not support Stickiness")
			}
		}
	}

	// Network Load Balancers have many special qwirks to them.
	// See http://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html
	if healthChecks := diff.Get("health_check").([]interface{}); len(healthChecks) == 1 {
		healthCheck := healthChecks[0].(map[string]interface{})
		protocol := healthCheck["protocol"].(string)

		if protocol == elbv2.ProtocolEnumTcp {
			// Cannot set custom matcher on TCP health checks
			if m := healthCheck["matcher"].(string); m != "" {
				return fmt.Errorf("%s: health_check.matcher is not supported for target_groups with TCP protocol", diff.Id())
			}
			// Cannot set custom path on TCP health checks
			if m := healthCheck["path"].(string); m != "" {
				return fmt.Errorf("%s: health_check.path is not supported for target_groups with TCP protocol", diff.Id())
			}
			// Cannot set custom timeout on TCP health checks
			if t := healthCheck["timeout"].(int); t != 0 && diff.Id() == "" {
				// timeout has a default value, so only check this if this is a network
				// LB and is a first run
				return fmt.Errorf("%s: health_check.timeout is not supported for target_groups with TCP protocol", diff.Id())
			}
			if healthCheck["healthy_threshold"].(int) != healthCheck["unhealthy_threshold"].(int) {
				return fmt.Errorf("%s: health_check.healthy_threshold %d and health_check.unhealthy_threshold %d must be the same for target_groups with TCP protocol", diff.Id(), healthCheck["healthy_threshold"].(int), healthCheck["unhealthy_threshold"].(int))
			}
		}
	}

	if strings.Contains(protocol, elbv2.ProtocolEnumHttp) {
		if healthChecks := diff.Get("health_check").([]interface{}); len(healthChecks) == 1 {
			healthCheck := healthChecks[0].(map[string]interface{})
			// HTTP(S) Target Groups cannot use TCP health checks
			if p := healthCheck["protocol"].(string); strings.ToLower(p) == "tcp" {
				return fmt.Errorf("HTTP Target Groups cannot use TCP health checks")
			}
		}
	}

	if diff.Id() == "" {
		return nil
	}

	if protocol == elbv2.ProtocolEnumTcp {
		if diff.HasChange("health_check.0.interval") {
			old, new := diff.GetChange("health_check.0.interval")
			return fmt.Errorf("Health check interval cannot be updated from %d to %d for TCP based Target Group %s,"+
				" use 'terraform taint' to recreate the resource if you wish",
				old, new, diff.Id())
		}
		if diff.HasChange("health_check.0.timeout") {
			old, new := diff.GetChange("health_check.0.timeout")
			return fmt.Errorf("Health check timeout cannot be updated from %d to %d for TCP based Target Group %s,"+
				" use 'terraform taint' to recreate the resource if you wish",
				old, new, diff.Id())
		}
	}
	return nil
}
