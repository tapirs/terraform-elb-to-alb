package elbtoalb

import (
	"bytes"
	"fmt"
	"regexp"
	"time"
	"log"
	"os"
	"bufio"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

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

	var lbName string
	if v, ok := d.GetOk("name"); ok {
		lbName = strings.Replace(v.(string), "elb-", "lb-", 1)
	} else if v, ok := d.GetOk("name_prefix"); ok {
		lbName = resource.PrefixedUniqueId(v.(string))
	} else {
		lbName = resource.PrefixedUniqueId("tf-lb-")
	}

	log.Println(d.Get("access_logs"))
	internal := d.Get("internal")
	cz_lb := d.Get("cross_zone_load_balancing")
	idle_timeout := d.Get("idle_timeout")


	security_groups_list := expandStringSet(d.Get("security_groups").(*schema.Set))
	var security_groups []string
	for _, sg := range security_groups_list {
		security_groups = append(security_groups, fmt.Sprintf("\"%s\"", *sg))
	}

	subnets_list := expandStringSet(d.Get("subnets").(*schema.Set))
	var subnets []string
	for _, sn := range subnets_list {
		log.Println(sn)
		subnets = append(subnets, fmt.Sprintf("\"%s\",", *sn))
	}

	deletion_protection := true

	access_logs_list := d.Get("access_logs").([]interface {})
	access_logs := "{\n"
	for key, val := range access_logs_list[0].(map[string]interface {}) {
		var s string
		switch val.(type) {
    case int:
			s = fmt.Sprintf("%s = %d", key, val)
    case float64:
			s = fmt.Sprintf("%s = %d", key, val)
    case string:
			val = strings.Replace(val.(string), "elb-", "lb-", 1)
			s = fmt.Sprintf("%s = \"%s\"", key, val)
    case bool:
			s = fmt.Sprintf("%s = %t", key, val)
    }
		access_logs = access_logs + s + "\n"
	}
	access_logs = access_logs + "}"

	tags := "{\n"
	for key, val := range d.Get("tags").(map[string]interface {}) {
		var s string
		switch val.(type) {
    case int:
			s = fmt.Sprintf("%s = %d", key, val)
    case float64:
			s = fmt.Sprintf("%s = %d", key, val)
    case string:
			val = strings.Replace(val.(string), "elb", "lb", 1)
			s = fmt.Sprintf("%s = \"%s\"", key, val)
    case bool:
			s = fmt.Sprintf("%s = %t", key, val)
    }
		tags = tags + s + "\n"
	}
	tags = tags + "}"

	err := os.MkdirAll("./lb_terraform/", 0755)
	if err != nil {
      return err
  }

	f, err := os.Create(fmt.Sprintf("./lb_terraform/%s.tf", lbName))
	if err != nil {
      return err
  }

	defer f.Close()

	w := bufio.NewWriter(f)
  _, err = w.WriteString(fmt.Sprintf("resource \"aws_lb\" \"%s\" {\nname = \"%s\"\ninternal = \"%t\"\nload_balancer_type = \"application\"\nsecurity_groups = %v\nsubnets = %v\n\nenable_deletion_protection = %t\nenable_cross_zone_load_balancing = %t\nidle_timeout = %d\n\naccess_logs %v\n\ntags = %v\n}", lbName, lbName, internal, security_groups, subnets, deletion_protection, cz_lb, idle_timeout, access_logs, tags))
	if err != nil {
      return err
  }

	w.Flush()

	return nil
}

func resourceElbtoalbLbRead(d *schema.ResourceData, meta interface{}) error {
	log.Println("in read")

	return nil
}

func resourceElbtoalbLbDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("in delete")

	return nil
}

func suppressIfLBType(t string) schema.SchemaDiffSuppressFunc {
	return func(k string, old string, new string, d *schema.ResourceData) bool {
		return d.Get("load_balancer_type").(string) == t
	}
}

func getLbNameFromArn(arn string) (string, error) {
	re := regexp.MustCompile("([^/]+/[^/]+/[^/]+)$")
	matches := re.FindStringSubmatch(arn)
	if len(matches) != 2 {
		return "", fmt.Errorf("Unexpected ARN format: %q", arn)
	}

	// e.g. app/example-alb/b26e625cdde161e6
	return matches[1], nil
}

// flattenSubnetsFromAvailabilityZones creates a slice of strings containing the subnet IDs
// for the ALB based on the AvailabilityZones structure returned by the API.
func flattenSubnetsFromAvailabilityZones(availabilityZones []*elbv2.AvailabilityZone) []string {
	var result []string
	for _, az := range availabilityZones {
		result = append(result, aws.StringValue(az.SubnetId))
	}
	return result
}

func flattenSubnetMappingsFromAvailabilityZones(availabilityZones []*elbv2.AvailabilityZone) []map[string]interface{} {
	l := make([]map[string]interface{}, 0)
	for _, availabilityZone := range availabilityZones {
		m := make(map[string]interface{})
		m["subnet_id"] = aws.StringValue(availabilityZone.SubnetId)

		for _, loadBalancerAddress := range availabilityZone.LoadBalancerAddresses {
			m["allocation_id"] = aws.StringValue(loadBalancerAddress.AllocationId)
		}

		l = append(l, m)
	}
	return l
}

func lbSuffixFromARN(arn *string) string {
	if arn == nil {
		return ""
	}

	if arnComponents := regexp.MustCompile(`arn:.*:loadbalancer/(.*)`).FindAllStringSubmatch(*arn, -1); len(arnComponents) == 1 {
		if len(arnComponents[0]) == 2 {
			return arnComponents[0][1]
		}
	}

	return ""
}

// flattenAwsLbResource takes a *elbv2.LoadBalancer and populates all respective resource fields.
func flattenAwsLbResource(d *schema.ResourceData, meta interface{}, lb *elbv2.LoadBalancer) error {
	// elbconn := meta.(*AWSClient).elbv2conn

	d.Set("arn", lb.LoadBalancerArn)
	d.Set("arn_suffix", lbSuffixFromARN(lb.LoadBalancerArn))
	d.Set("name", lb.LoadBalancerName)
	d.Set("internal", (lb.Scheme != nil && aws.StringValue(lb.Scheme) == "internal"))
	d.Set("security_groups", flattenStringList(lb.SecurityGroups))
	d.Set("vpc_id", lb.VpcId)
	d.Set("zone_id", lb.CanonicalHostedZoneId)
	d.Set("dns_name", lb.DNSName)
	d.Set("ip_address_type", lb.IpAddressType)
	d.Set("load_balancer_type", lb.Type)

	if err := d.Set("subnets", flattenSubnetsFromAvailabilityZones(lb.AvailabilityZones)); err != nil {
		return fmt.Errorf("error setting subnets: %s", err)
	}

	if err := d.Set("subnet_mapping", flattenSubnetMappingsFromAvailabilityZones(lb.AvailabilityZones)); err != nil {
		return fmt.Errorf("error setting subnet_mapping: %s", err)
	}

	// tags, err := keyvaluetags.Elbv2ListTags(elbconn, d.Id())

	// if err != nil {
	// 	return fmt.Errorf("error listing tags for (%s): %s", d.Id(), err)
	// }

	// if err := d.Set("tags", tags.IgnoreAws().Map()); err != nil {
	// 	return fmt.Errorf("error setting tags: %s", err)
	// }

	// attributesResp, err := elbconn.DescribeLoadBalancerAttributes(&elbv2.DescribeLoadBalancerAttributesInput{
	// 	LoadBalancerArn: aws.String(d.Id()),
	// })
	// if err != nil {
	// 	return fmt.Errorf("Error retrieving LB Attributes: %s", err)
	// }

	// accessLogMap := map[string]interface{}{
	// 	"bucket":  "",
	// 	"enabled": false,
	// 	"prefix":  "",
	// }

	// for _, attr := range attributesResp.Attributes {
	// 	switch aws.StringValue(attr.Key) {
	// 	case "access_logs.s3.enabled":
	// 		accessLogMap["enabled"] = aws.StringValue(attr.Value) == "true"
	// 	case "access_logs.s3.bucket":
	// 		accessLogMap["bucket"] = aws.StringValue(attr.Value)
	// 	case "access_logs.s3.prefix":
	// 		accessLogMap["prefix"] = aws.StringValue(attr.Value)
	// 	case "idle_timeout.timeout_seconds":
	// 		timeout, err := strconv.Atoi(aws.StringValue(attr.Value))
	// 		if err != nil {
	// 			return fmt.Errorf("Error parsing ALB timeout: %s", err)
	// 		}
	// 		log.Printf("[DEBUG] Setting ALB Timeout Seconds: %d", timeout)
	// 		d.Set("idle_timeout", timeout)
	// 	case "routing.http.drop_invalid_header_fields.enabled":
	// 		dropInvalidHeaderFieldsEnabled := aws.StringValue(attr.Value) == "true"
	// 		log.Printf("[DEBUG] Setting LB Invalid Header Fields Enabled: %t", dropInvalidHeaderFieldsEnabled)
	// 		d.Set("drop_invalid_header_fields", dropInvalidHeaderFieldsEnabled)
	// 	case "deletion_protection.enabled":
	// 		protectionEnabled := aws.StringValue(attr.Value) == "true"
	// 		log.Printf("[DEBUG] Setting LB Deletion Protection Enabled: %t", protectionEnabled)
	// 		d.Set("enable_deletion_protection", protectionEnabled)
	// 	case "routing.http2.enabled":
	// 		http2Enabled := aws.StringValue(attr.Value) == "true"
	// 		log.Printf("[DEBUG] Setting ALB HTTP/2 Enabled: %t", http2Enabled)
	// 		d.Set("enable_http2", http2Enabled)
	// 	case "load_balancing.cross_zone.enabled":
	// 		crossZoneLbEnabled := aws.StringValue(attr.Value) == "true"
	// 		log.Printf("[DEBUG] Setting NLB Cross Zone Load Balancing Enabled: %t", crossZoneLbEnabled)
	// 		d.Set("enable_cross_zone_load_balancing", crossZoneLbEnabled)
	// 	}
	// }
	//
	// if err := d.Set("access_logs", []interface{}{accessLogMap}); err != nil {
	// 	return fmt.Errorf("error setting access_logs: %s", err)
	// }

	return nil
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
