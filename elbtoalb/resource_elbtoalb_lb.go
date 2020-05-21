package elbtoalb

import (
	"bytes"
	"fmt"
	// "regexp"
	"time"
	"log"
	"os"
	"bufio"
	"strings"
	// "io/ioutil"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	// "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

type LB struct {
	Name string
	Internal bool
	Load_balancer_type string
	Security_groups []string
	Subnets []string

	Enable_deletion_protection bool
	Enable_cross_zone_load_balancing bool
	Idle_timeout int

	Access_logs Access_logs

	Tags map[string]interface{}
}

type Access_logs struct {
	Bucket string
	Prefix string
	Enabled bool
}

var lb LB

func resourceElbtoalbLb() *schema.Resource {
	return &schema.Resource{
		// Subnets are ForceNew for Network Load Balancers
		CustomizeDiff: customizeDiffNLBSubnets,
		Create: resourceElbtoalbLbCreate,
		Read: resourceElbtoalbLbRead,
		Delete: resourceElbtoalbLbDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
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
				ValidateFunc:  validateElbName,
			},

			"name_prefix": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name"},
				ValidateFunc:  validateElbNamePrefix,
			},

			"internal": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"load_balancer_type": {
				Type:     schema.TypeString,
				ForceNew: true,
				Optional: true,
				Default:  elbv2.LoadBalancerTypeEnumApplication,
				ValidateFunc: validation.StringInSlice([]string{
					elbv2.LoadBalancerTypeEnumApplication,
					elbv2.LoadBalancerTypeEnumNetwork,
				}, false),
			},

			"security_groups": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
				Optional: true,
				Set:      schema.HashString,
			},

			"subnets": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Set:      schema.HashString,
			},

			"subnet_mapping": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subnet_id": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"allocation_id": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
					},
				},
				Set: func(v interface{}) int {
					var buf bytes.Buffer
					m := v.(map[string]interface{})
					buf.WriteString(fmt.Sprintf("%s-", m["subnet_id"].(string)))
					if m["allocation_id"] != "" {
						buf.WriteString(fmt.Sprintf("%s-", m["allocation_id"].(string)))
					}
					return hashcode.String(buf.String())
				},
			},

			"access_logs": {
				Type:             schema.TypeList,
				Optional:         true,
				ForceNew: true,
				MaxItems:         1,
				DiffSuppressFunc: suppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"bucket": {
							Type:     schema.TypeString,
							Required: true,
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								return !d.Get("access_logs.0.enabled").(bool)
							},
						},
						"prefix": {
							Type:     schema.TypeString,
							Optional: true,
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								return !d.Get("access_logs.0.enabled").(bool)
							},
						},
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},

			"enable_deletion_protection": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"idle_timeout": {
				Type:             schema.TypeInt,
				Optional:         true,
				ForceNew: true,
				Default:          60,
				DiffSuppressFunc: suppressIfLBType(elbv2.LoadBalancerTypeEnumNetwork),
			},

			"drop_invalid_header_fields": {
				Type:             schema.TypeBool,
				Optional:         true,
				ForceNew: true,
				Default:          false,
				DiffSuppressFunc: suppressIfLBType("network"),
			},

			"enable_cross_zone_load_balancing": {
				Type:             schema.TypeBool,
				Optional:         true,
				ForceNew: true,
				Default:          false,
				DiffSuppressFunc: suppressIfLBType(elbv2.LoadBalancerTypeEnumApplication),
			},

			"enable_http2": {
				Type:             schema.TypeBool,
				Optional:         true,
				ForceNew: true,
				Default:          true,
				DiffSuppressFunc: suppressIfLBType(elbv2.LoadBalancerTypeEnumNetwork),
			},

			"ip_address_type": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					elbv2.IpAddressTypeIpv4,
					elbv2.IpAddressTypeDualstack,
				}, false),
			},

			"vpc_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"zone_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"dns_name": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchemaForceNew(),
		},
	}
}

func resourceElbtoalbLbCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("in lb create")

	resourceElbtoalbLbRead(d, meta)

	lbName := "lb-e2a-env-br"

	internal := d.Get("internal")
	cz_lb := d.Get("cross_zone_load_balancing")
	idle_timeout := d.Get("idle_timeout")


	security_groups_list := expandStringSet(d.Get("security_groups").(*schema.Set))
	security_groups := lb.Security_groups
	for _, sg := range security_groups_list {
		if !strings.Contains(strings.Join(security_groups, ", "), fmt.Sprintf("\"%s\"", *sg)) {
			security_groups = append(security_groups, fmt.Sprintf("\"%s\"", *sg))
		}

	}

	subnets_list := expandStringSet(d.Get("subnets").(*schema.Set))
	subnets := lb.Subnets
	for _, sn := range subnets_list {
		if !strings.Contains(strings.Join(subnets, ", "), fmt.Sprintf("\"%s\"", *sn)) {
			subnets = append(subnets, fmt.Sprintf("\"%s\"", *sn))
		}
	}

	deletion_protection := true

	access_logs_list := d.Get("access_logs").([]interface {})
	var access_logs Access_logs
	access_logs.Bucket = lb.Access_logs.Bucket
	if len(access_logs_list) > 0 {
		for key, val := range access_logs_list[0].(map[string]interface {}) {
			if key == "bucket" {
				access_logs.Bucket = val.(string)
				break
			}
		}
	}

	access_logs.Prefix = lb.Name
	access_logs.Enabled = true

	// tags := "{\n"
	// for key, val := range d.Get("tags").(map[string]interface {}) {
	// 	var s string
	// 	switch val.(type) {
  //   case int:
	// 		s = fmt.Sprintf("%s = %d", key, val)
  //   case float64:
	// 		s = fmt.Sprintf("%s = %d", key, val)
  //   case string:
	// 		val = strings.Replace(val.(string), "elb", "lb", 1)
	// 		s = fmt.Sprintf("%s = \"%s\"", key, val)
  //   case bool:
	// 		s = fmt.Sprintf("%s = %t", key, val)
  //   }
	// 	tags = tags + s + "\n"
	// }
	// tags = tags + "}"

	var tags map[string]interface{}
	if lb.Tags == nil {
		tags = make(map[string]interface{})
	} else {
		tags = lb.Tags
	}

	for key, val := range d.Get("tags").(map[string]interface {}) {
		log.Println("Tag is - " + key + ":" + val.(string))
		if tags[key] != nil {
			tags[key] = tags[key].(string) + val.(string) + " "
		} else {
			tags[key] = val.(string) + " "
		}

	}


	lb.Name = lbName
	lb.Internal = internal.(bool)
	lb.Load_balancer_type = "application"
	lb.Security_groups = security_groups
	lb.Subnets = subnets
	lb.Enable_deletion_protection = deletion_protection
	lb.Enable_cross_zone_load_balancing = cz_lb.(bool)
	lb.Idle_timeout = idle_timeout.(int)
	lb.Access_logs = access_logs
	lb.Tags = tags

	err := os.MkdirAll("./lb_terraform/", 0755)
	if err != nil {
      return err
  }

	f, err := os.Create("./lb_terraform/lb.tf")
	if err != nil {
      return err
  }

	w := bufio.NewWriter(f)

	// removed tags for now
	// _, err = w.WriteString(fmt.Sprintf("resource \"aws_lb\" \"%s\" {\nname = \"%s\"\ninternal = %t\nload_balancer_type = \"application\"\nsecurity_groups = [%v]\nsubnets = [%v]\n\nenable_deletion_protection = %t\nenable_cross_zone_load_balancing = %t\nidle_timeout = %d\n\naccess_logs {\nbucket = \"%v\"\nprefix = \"%v\"\nenabled = %v\n}\n\ntags = {\ntags = \"%v\"\n}\n}", lb.Name, lb.Name, lb.Internal, strings.Join(lb.Security_groups, ", "), strings.Join(lb.Subnets, ", "), lb.Enable_deletion_protection, lb.Enable_cross_zone_load_balancing, lb.Idle_timeout, lb.Access_logs.Bucket, lb.Access_logs.Prefix, lb.Access_logs.Enabled, lb.Tags["tags"]))
	_, err = w.WriteString(fmt.Sprintf("resource \"aws_lb\" \"%s\" {\nname = \"%s\"\ninternal = %t\nload_balancer_type = \"application\"\nsecurity_groups = [%v]\nsubnets = [%v]\n\nenable_deletion_protection = %t\nenable_cross_zone_load_balancing = %t\nidle_timeout = %d\n\naccess_logs {\nbucket = \"%v\"\nprefix = \"%v\"\nenabled = %v\n}\n}", lb.Name, lb.Name, lb.Internal, strings.Join(lb.Security_groups, ", "), strings.Join(lb.Subnets, ", "), lb.Enable_deletion_protection, lb.Enable_cross_zone_load_balancing, lb.Idle_timeout, lb.Access_logs.Bucket, lb.Access_logs.Prefix, lb.Access_logs.Enabled))

	if err != nil {
      return err
  }

	w.Flush()

	return nil
}

func resourceElbtoalbLbRead(d *schema.ResourceData, meta interface{}) error {

	return nil
}

func resourceElbtoalbLbDelete(d *schema.ResourceData, meta interface{}) error {

	return nil
}

func suppressIfLBType(t string) schema.SchemaDiffSuppressFunc {
	return func(k string, old string, new string, d *schema.ResourceData) bool {
		return d.Get("load_balancer_type").(string) == t
	}
}

// Load balancers of type 'network' cannot have their subnets updated at
// this time. If the type is 'network' and subnets have changed, mark the
// diff as a ForceNew operation
func customizeDiffNLBSubnets(diff *schema.ResourceDiff, v interface{}) error {
	// The current criteria for determining if the operation should be ForceNew:
	// - lb of type "network"
	// - existing resource (id is not "")
	// - there are actual changes to be made in the subnets
	//
	// Any other combination should be treated as normal. At this time, subnet
	// handling is the only known difference between Network Load Balancers and
	// Application Load Balancers, so the logic below is simple individual checks.
	// If other differences arise we'll want to refactor to check other
	// conditions in combinations, but for now all we handle is subnets
	if lbType := diff.Get("load_balancer_type").(string); lbType != elbv2.LoadBalancerTypeEnumNetwork {
		return nil
	}

	if diff.Id() == "" {
		return nil
	}

	o, n := diff.GetChange("subnets")
	if o == nil {
		o = new(schema.Set)
	}
	if n == nil {
		n = new(schema.Set)
	}
	os := o.(*schema.Set)
	ns := n.(*schema.Set)
	remove := os.Difference(ns).List()
	add := ns.Difference(os).List()
	if len(remove) > 0 || len(add) > 0 {
		if err := diff.SetNew("subnets", n); err != nil {
			return err
		}

		if err := diff.ForceNew("subnets"); err != nil {
			return err
		}
	}
	return nil
}
