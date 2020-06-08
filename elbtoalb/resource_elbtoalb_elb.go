package elbtoalb

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/tapirs/terraform-elb-to-alb/elbtoalb/internal/keyvaluetags"
)

func resourceElbtoalbElb() *schema.Resource {
	log.Println("in resource elb")
	return &schema.Resource{
		Create: resourceElbtoalbElbCreate,
		Read:   resourceElbtoalbElbRead,
		Delete: resourceElbtoalbElbDelete,
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
				ForceNew: true,
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
				ForceNew:     true,
				Default:      60,
				ValidateFunc: validation.IntBetween(1, 4000),
			},

			"connection_draining": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"connection_draining_timeout": {
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
				Default:  300,
			},

			"access_logs": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
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
				ForceNew: true,
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
				Set: resourceElbtoalbElbListenerHash,
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

			"tags": tagsSchemaForceNew(),
		},
	}
}

func resourceElbtoalbElbCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("in create")

	// Expand the "listener" set to aws-sdk-go compat []*elb.Listener
	listeners, err := expandListeners(d.Get("listener").(*schema.Set).List())
	if err != nil {
		return err
	}

	log.Println(listeners)

	var elbName string
	if v, ok := d.GetOk("name"); ok {
		elbName = v.(string)
	} else {
		if v, ok := d.GetOk("name_prefix"); ok {
			elbName = resource.PrefixedUniqueId(v.(string))
		} else {
			elbName = resource.PrefixedUniqueId("tf-lb-")
		}
		err = d.Set("name", elbName)
		if err != nil {
			return err
		}
	}

	tags := keyvaluetags.New(d.Get("tags").(map[string]interface{})).IgnoreAws().ElbTags()

	d.SetId(elbName)
	log.Printf("[INFO] ELB ID: %s", d.Id())

	if err = d.Set("tags", keyvaluetags.ElbKeyValueTags(tags).IgnoreAws().Map()); err != nil {
		return fmt.Errorf("error setting tags: %s", err)
	}

	if err := resourceElbtoalbLbCreate(d, meta); err != nil {
		return fmt.Errorf("error creating Lb Target Group: %s", err)
	}

	if err := resourceElbtoalbLbTargetGroupCreate(d, meta); err != nil {
		return fmt.Errorf("error creating Lb: %s", err)
	}

	if err := resourceElbtoalbLbListenerCreate(d, meta); err != nil {
		return fmt.Errorf("error creating Lb Listener: %s", err)
	}

	if err := resourceElbtoalbLbListenerRuleCreate(d, meta); err != nil {
		return fmt.Errorf("error creating Lb Listener Rule: %s", err)
	}

	return nil
}

func resourceElbtoalbElbRead(d *schema.ResourceData, meta interface{}) error {
	log.Println("in read")

	return nil
}

func resourceElbtoalbElbDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("in delete")

	return nil
}

func resourceElbtoalbElbListenerHash(v interface{}) int {
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
