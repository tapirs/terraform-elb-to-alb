package elbtoalb

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

func resourceElbtoalbLbbListenerRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceElbtoalbLbListenerRuleCreate,
		Read:   resourceElbtoalbLbListenerRuleRead,
		Delete: resourceElbtoalbLbListenerRuleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"listener_arn": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"priority": {
				Type:         schema.TypeInt,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				ValidateFunc: validateAwsLbListenerRulePriority,
			},
			"action": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								elbv2.ActionTypeEnumAuthenticateCognito,
								elbv2.ActionTypeEnumAuthenticateOidc,
								elbv2.ActionTypeEnumFixedResponse,
								elbv2.ActionTypeEnumForward,
								elbv2.ActionTypeEnumRedirect,
							}, true),
						},
						"order": {
							Type:         schema.TypeInt,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validation.IntBetween(1, 50000),
						},

						"target_group_arn": {
							Type:             schema.TypeString,
							Optional:         true,
							DiffSuppressFunc: suppressIfActionTypeNot("forward"),
						},

						"redirect": {
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: suppressIfActionTypeNot("redirect"),
							MaxItems:         1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"host": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "#{host}",
									},

									"path": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "/#{path}",
									},

									"port": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "#{port}",
									},

									"protocol": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "#{protocol}",
										ValidateFunc: validation.StringInSlice([]string{
											"#{protocol}",
											"HTTP",
											"HTTPS",
										}, false),
									},

									"query": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "#{query}",
									},

									"status_code": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice([]string{
											"HTTP_301",
											"HTTP_302",
										}, false),
									},
								},
							},
						},

						"fixed_response": {
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: suppressIfActionTypeNot("fixed-response"),
							MaxItems:         1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"content_type": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice([]string{
											"text/plain",
											"text/css",
											"text/html",
											"application/javascript",
											"application/json",
										}, false),
									},

									"message_body": {
										Type:     schema.TypeString,
										Optional: true,
									},

									"status_code": {
										Type:         schema.TypeString,
										Optional:     true,
										Computed:     true,
										ValidateFunc: validation.StringMatch(regexp.MustCompile(`^[245]\d\d$`), ""),
									},
								},
							},
						},

						"authenticate_cognito": {
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: suppressIfActionTypeNot(elbv2.ActionTypeEnumAuthenticateCognito),
							MaxItems:         1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"authentication_request_extra_params": {
										Type:     schema.TypeMap,
										Optional: true,
									},
									"on_unauthenticated_request": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
										ValidateFunc: validation.StringInSlice([]string{
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumDeny,
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumAllow,
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumAuthenticate,
										}, true),
									},
									"scope": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_cookie_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_timeout": {
										Type:     schema.TypeInt,
										Optional: true,
										Computed: true,
									},
									"user_pool_arn": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_pool_client_id": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_pool_domain": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},

						"authenticate_oidc": {
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: suppressIfActionTypeNot(elbv2.ActionTypeEnumAuthenticateOidc),
							MaxItems:         1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"authentication_request_extra_params": {
										Type:     schema.TypeMap,
										Optional: true,
									},
									"authorization_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
									"client_id": {
										Type:     schema.TypeString,
										Required: true,
									},
									"client_secret": {
										Type:      schema.TypeString,
										Required:  true,
										Sensitive: true,
									},
									"issuer": {
										Type:     schema.TypeString,
										Required: true,
									},
									"on_unauthenticated_request": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
										ValidateFunc: validation.StringInSlice([]string{
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumDeny,
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumAllow,
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumAuthenticate,
										}, true),
									},
									"scope": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_cookie_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_timeout": {
										Type:     schema.TypeInt,
										Optional: true,
										Computed: true,
									},
									"token_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_info_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"condition": {
				Type:     schema.TypeSet,
				Required: true,
				ForceNew: true,
				Set:      lbListenerRuleConditionSetHash,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"field": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
							ValidateFunc: validation.StringInSlice([]string{
								"host-header",
								"path-pattern",
							}, true),
							Deprecated: "use 'host_header' or 'path_pattern' attribute instead",
						},
						"host_header": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true, // Deprecated: remove Computed
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"values": {
										Type: schema.TypeSet,
										// Deprecated: Change Optional & Computed to Required in next major version of the provider
										Optional: true,
										Computed: true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringLenBetween(1, 128),
										},
										Set: schema.HashString,
									},
								},
							},
						},
						"http_header": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"http_header_name": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringMatch(regexp.MustCompile("^[A-Za-z0-9!#$%&'*+-.^_`|~]{1,40}$"), ""),
									},
									"values": {
										Type: schema.TypeSet,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringLenBetween(1, 128),
										},
										Required: true,
										Set:      schema.HashString,
									},
								},
							},
						},
						"http_request_method": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"values": {
										Type: schema.TypeSet,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringMatch(regexp.MustCompile(`^[A-Za-z-_]{1,40}$`), ""),
										},
										Required: true,
										Set:      schema.HashString,
									},
								},
							},
						},
						"path_pattern": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true, // Deprecated: remove Computed
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"values": {
										Type: schema.TypeSet,
										// Deprecated: Change Optional & Computed to Required in next major version of the provider
										Optional: true,
										Computed: true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringLenBetween(1, 128),
										},
										Set: schema.HashString,
									},
								},
							},
						},
						"query_string": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
							Set: lbListenerRuleConditionQueryStringHash,
						},
						"source_ip": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"values": {
										Type: schema.TypeSet,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validateCIDRNetworkAddress,
										},
										Required: true,
										Set:      schema.HashString,
									},
								},
							},
						},
						"values": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringLenBetween(1, 128),
							},
							Optional:   true,
							Computed:   true,
							Deprecated: "use 'host_header' or 'path_pattern' attribute instead",
						},
					},
				},
			},
		},
	}
}

func resourceElbtoalbLbListenerRuleCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("in lb listener rule create")

	// Expand the "listener" set to aws-sdk-go compat []*elb.Listener
	listeners, err := expandListeners(d.Get("listener").(*schema.Set).List())
	if err != nil {
		return err
	}

	for _, listener := range listeners {
		log.Println(listener)

		lbPort := *listener.LoadBalancerPort
		instancePort := *listener.InstancePort

		var listenerRuleName string
		var listenerArn string
		var targetGroupArn string
		var hostHeader string
		if v, ok := d.GetOk("name"); ok {
			listenerRuleName = strings.Replace(v.(string), "elb-", "listenerRule-", 1) + "-" + strconv.FormatInt(lbPort, 10) + "-" + strconv.FormatInt(instancePort, 10)
			listenerArn = "aws_lb_listener." + "listener-" + strconv.FormatInt(lbPort, 10) + ".arn"
			targetGroupArn = "aws_lb_target_group." + strings.Replace(v.(string), "elb-", "tg-", 1) + "-" + strconv.FormatInt(instancePort, 10) + ".arn"
			hostHeader = "*" + strings.Replace(v.(string), "elb-", "", 1) + "domain-name"
		}

		targetGroupArn = strings.ReplaceAll(targetGroupArn, "-e2a-env-br", "")
		resourceName := strings.ReplaceAll(listenerRuleName, "-e2a-env-br", "")

		err := os.MkdirAll("./lb_terraform/listener_rule", 0755)
		if err != nil {
			return err
		}

		f, err := os.Create(fmt.Sprintf("./lb_terraform/listener_rule/%s.tf", resourceName))
		if err != nil {
			return err
		}

		defer f.Close()

		s1 := rand.NewSource(time.Now().UnixNano())
		r1 := rand.New(s1)

		w := bufio.NewWriter(f)
		_, err = w.WriteString(fmt.Sprintf("resource \"aws_lb_listener_rule\" \"%s\" {\nlistener_arn = %s\npriority = %d\n\naction {\ntype = \"forward\"\ntarget_group_arn = %s\n}\n\ncondition {\nhost_header {\nvalues = [\"%s\"]\n}\n}\n}", listenerRuleName, listenerArn, r1.Intn(50000), targetGroupArn, hostHeader))
		if err != nil {
			return err
		}

		w.Flush()
	}

	return nil
}

func resourceElbtoalbLbListenerRuleRead(d *schema.ResourceData, meta interface{}) error {
	log.Println("in read")

	return nil
}

func resourceElbtoalbLbListenerRuleDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("in delete")

	return nil
}

/* DEPRECATED Backwards compatibility: This primarily exists to set a hash that handles the values to host_header or path_pattern migration.
Can probably be removed on the next major version of the provider.
*/
func lbListenerRuleConditionSetHash(v interface{}) int {
	if v == nil {
		return 0
	}

	var field string
	var buf strings.Builder

	m := v.(map[string]interface{})

	if hostHeader, ok := m["host_header"].([]interface{}); ok && len(hostHeader) > 0 {
		if hostHeader[0] != nil {
			field = "host-header"
			values := hostHeader[0].(map[string]interface{})["values"].(*schema.Set)
			for _, l := range values.List() {
				fmt.Fprint(&buf, l, "-")
			}
		}
	} else if m["field"].(string) == "host-header" {
		// Backwards compatibility
		field = "host-header"
		for _, l := range m["values"].([]interface{}) {
			fmt.Fprint(&buf, l, "-")
		}
	}

	if httpHeader, ok := m["http_header"].([]interface{}); ok && len(httpHeader) > 0 && httpHeader[0] != nil {
		field = "http-header"
		httpHeaderMap := httpHeader[0].(map[string]interface{})
		fmt.Fprint(&buf, httpHeaderMap["http_header_name"].(string), ":")
		httpHeaderValues := httpHeaderMap["values"].(*schema.Set)
		for _, l := range httpHeaderValues.List() {
			fmt.Fprint(&buf, l, "-")
		}
	}

	if httpRequestMethod, ok := m["http_request_method"].([]interface{}); ok && len(httpRequestMethod) > 0 && httpRequestMethod[0] != nil {
		field = "http-request-method"
		values := httpRequestMethod[0].(map[string]interface{})["values"].(*schema.Set)
		for _, l := range values.List() {
			fmt.Fprint(&buf, l, "-")
		}
	}

	if pathPattern, ok := m["path_pattern"].([]interface{}); ok && len(pathPattern) > 0 {
		if pathPattern[0] != nil {
			field = "path-pattern"
			values := pathPattern[0].(map[string]interface{})["values"].(*schema.Set)
			for _, l := range values.List() {
				fmt.Fprint(&buf, l, "-")
			}
		}
	} else if m["field"].(string) == "path-pattern" {
		// Backwards compatibility
		field = "path-pattern"
		for _, l := range m["values"].([]interface{}) {
			fmt.Fprint(&buf, l, "-")
		}
	}

	if queryString, ok := m["query_string"].(*schema.Set); ok && queryString.Len() > 0 {
		field = "query-string"
		for _, l := range queryString.List() {
			fmt.Fprint(&buf, lbListenerRuleConditionQueryStringHash(l), "-")
		}
	}

	if sourceIp, ok := m["source_ip"].([]interface{}); ok && len(sourceIp) > 0 && sourceIp[0] != nil {
		field = "source-ip"
		values := sourceIp[0].(map[string]interface{})["values"].(*schema.Set)
		for _, l := range values.List() {
			fmt.Fprint(&buf, l, "-")
		}
	}

	return hashcode.String(fmt.Sprintf("%s-%s", field, buf.String()))
}

func lbListenerRuleConditionQueryStringHash(v interface{}) int {
	m := v.(map[string]interface{})
	return hashcode.String(fmt.Sprintf("%s-%s", m["key"], m["value"]))
}

func suppressIfActionTypeNot(t string) schema.SchemaDiffSuppressFunc {
	return func(k, old, new string, d *schema.ResourceData) bool {
		take := 2
		i := strings.IndexFunc(k, func(r rune) bool {
			if r == '.' {
				take -= 1
				return take == 0
			}
			return false
		})
		at := k[:i+1] + "type"
		return d.Get(at).(string) != t
	}
}

func validateAwsLbListenerRulePriority(v interface{}, k string) (ws []string, errors []error) {
	value := v.(int)
	if value < 1 || (value > 50000 && value != 99999) {
		errors = append(errors, fmt.Errorf("%q must be in the range 1-50000 for normal rule or 99999 for default rule", k))
	}
	return
}

// from arn:
// arn:aws:elasticloadbalancing:us-east-1:012345678912:listener-rule/app/name/0123456789abcdef/abcdef0123456789/456789abcedf1234
// select submatches:
// (arn:aws:elasticloadbalancing:us-east-1:012345678912:listener)-rule(/app/name/0123456789abcdef/abcdef0123456789)/456789abcedf1234
// concat to become:
// arn:aws:elasticloadbalancing:us-east-1:012345678912:listener/app/name/0123456789abcdef/abcdef0123456789
var lbListenerARNFromRuleARNRegexp = regexp.MustCompile(`^(arn:.+:listener)-rule(/.+)/[^/]+$`)

func lbListenerARNFromRuleARN(ruleArn string) string {
	if arnComponents := lbListenerARNFromRuleARNRegexp.FindStringSubmatch(ruleArn); len(arnComponents) > 1 {
		return arnComponents[1] + arnComponents[2]
	}

	return ""
}
