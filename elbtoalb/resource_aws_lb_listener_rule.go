package elbtoalb

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

func resourceAwsLbbListenerRule() *schema.Resource {
	return &schema.Resource{
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

func highestListenerRulePriority(conn *elbv2.ELBV2, arn string) (priority int64, err error) {
	var priorities []int
	var nextMarker *string

	for {
		out, aerr := conn.DescribeRules(&elbv2.DescribeRulesInput{
			ListenerArn: aws.String(arn),
			Marker:      nextMarker,
		})
		if aerr != nil {
			err = aerr
			return
		}
		for _, rule := range out.Rules {
			if aws.StringValue(rule.Priority) != "default" {
				p, _ := strconv.Atoi(aws.StringValue(rule.Priority))
				priorities = append(priorities, p)
			}
		}
		if out.NextMarker == nil {
			break
		}
		nextMarker = out.NextMarker
	}

	if len(priorities) == 0 {
		priority = 0
		return
	}

	sort.IntSlice(priorities).Sort()
	priority = int64(priorities[len(priorities)-1])

	return
}

// lbListenerRuleConditions converts data source generated by Terraform into
// an elbv2.RuleCondition object suitable for submitting to AWS API.
func lbListenerRuleConditions(conditions []interface{}) ([]*elbv2.RuleCondition, error) {
	elbConditions := make([]*elbv2.RuleCondition, len(conditions))
	for i, condition := range conditions {
		elbConditions[i] = &elbv2.RuleCondition{}
		conditionMap := condition.(map[string]interface{})
		var field string
		var attrs int

		if hostHeader, ok := conditionMap["host_header"].([]interface{}); ok && len(hostHeader) > 0 {
			field = "host-header"
			attrs += 1
			values := hostHeader[0].(map[string]interface{})["values"].(*schema.Set)

			elbConditions[i].HostHeaderConfig = &elbv2.HostHeaderConditionConfig{
				Values: expandStringSet(values),
			}
		}

		if httpHeader, ok := conditionMap["http_header"].([]interface{}); ok && len(httpHeader) > 0 {
			field = "http-header"
			attrs += 1
			httpHeaderMap := httpHeader[0].(map[string]interface{})
			values := httpHeaderMap["values"].(*schema.Set)

			elbConditions[i].HttpHeaderConfig = &elbv2.HttpHeaderConditionConfig{
				HttpHeaderName: aws.String(httpHeaderMap["http_header_name"].(string)),
				Values:         expandStringSet(values),
			}
		}

		if httpRequestMethod, ok := conditionMap["http_request_method"].([]interface{}); ok && len(httpRequestMethod) > 0 {
			field = "http-request-method"
			attrs += 1
			values := httpRequestMethod[0].(map[string]interface{})["values"].(*schema.Set)

			elbConditions[i].HttpRequestMethodConfig = &elbv2.HttpRequestMethodConditionConfig{
				Values: expandStringSet(values),
			}
		}

		if pathPattern, ok := conditionMap["path_pattern"].([]interface{}); ok && len(pathPattern) > 0 {
			field = "path-pattern"
			attrs += 1
			values := pathPattern[0].(map[string]interface{})["values"].(*schema.Set)

			elbConditions[i].PathPatternConfig = &elbv2.PathPatternConditionConfig{
				Values: expandStringSet(values),
			}
		}

		if queryString, ok := conditionMap["query_string"].(*schema.Set); ok && queryString.Len() > 0 {
			field = "query-string"
			attrs += 1
			values := queryString.List()

			elbConditions[i].QueryStringConfig = &elbv2.QueryStringConditionConfig{
				Values: make([]*elbv2.QueryStringKeyValuePair, len(values)),
			}
			for j, p := range values {
				valuePair := p.(map[string]interface{})
				elbValuePair := &elbv2.QueryStringKeyValuePair{
					Value: aws.String(valuePair["value"].(string)),
				}
				if valuePair["key"].(string) != "" {
					elbValuePair.Key = aws.String(valuePair["key"].(string))
				}
				elbConditions[i].QueryStringConfig.Values[j] = elbValuePair
			}
		}

		if sourceIp, ok := conditionMap["source_ip"].([]interface{}); ok && len(sourceIp) > 0 {
			field = "source-ip"
			attrs += 1
			values := sourceIp[0].(map[string]interface{})["values"].(*schema.Set)

			elbConditions[i].SourceIpConfig = &elbv2.SourceIpConditionConfig{
				Values: expandStringSet(values),
			}
		}

		// Deprecated backwards compatibility
		// This code is also hit during an update when the condition has not been modified. Issues: GH-11232 and GH-11362
		if cmField, ok := conditionMap["field"].(string); ok && (cmField == "host-header" || cmField == "path-pattern") {
			// When the condition is not being updated Terraform feeds in the existing state which has host header and
			// path pattern set in both locations with identical values.
			if field == cmField {
				values := schema.NewSet(schema.HashString, conditionMap["values"].([]interface{}))
				var values2 *schema.Set
				if cmField == "host-header" {
					values2 = conditionMap["host_header"].([]interface{})[0].(map[string]interface{})["values"].(*schema.Set)
				} else {
					values2 = conditionMap["path_pattern"].([]interface{})[0].(map[string]interface{})["values"].(*schema.Set)
				}
				if !values2.Equal(values) {
					attrs += 1
				}
			} else {
				field = cmField
				attrs += 1
				values := conditionMap["values"].([]interface{})
				if len(values) == 0 {
					return nil, errors.New("Both field and values must be set in a condition block")
				}
				elbConditions[i].Values = expandStringList(values)
			}
		}

		// FIXME Rework this and use ConflictsWith when it finally works with collections:
		// https://github.com/hashicorp/terraform/issues/13016
		// Still need to ensure that one of the condition attributes is set.
		if attrs == 0 {
			return nil, errors.New("One of host_header, http_header, http_request_method, path_pattern, query_string or source_ip must be set in a condition block")
		} else if attrs > 1 {
			// Deprecated: remove `field` from message
			return nil, errors.New("Only one of field, host_header, http_header, http_request_method, path_pattern, query_string or source_ip can be set in a condition block")
		}

		elbConditions[i].Field = aws.String(field)
	}
	return elbConditions, nil
}
