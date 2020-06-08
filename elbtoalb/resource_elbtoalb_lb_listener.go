package elbtoalb

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

func resourceElbtoalbLbListener() *schema.Resource {
	return &schema.Resource{
		Create: resourceElbtoalbLbListenerCreate,
		Read:   resourceElbtoalbLbListenerRead,
		Delete: resourceElbtoalbLbListenerDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(10 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"load_balancer_arn": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"port": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			"protocol": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "HTTP",
				StateFunc: func(v interface{}) string {
					return strings.ToUpper(v.(string))
				},
				ValidateFunc: validation.StringInSlice([]string{
					elbv2.ProtocolEnumHttp,
					elbv2.ProtocolEnumHttps,
					elbv2.ProtocolEnumTcp,
					elbv2.ProtocolEnumTls,
					elbv2.ProtocolEnumUdp,
					elbv2.ProtocolEnumTcpUdp,
				}, true),
			},

			"ssl_policy": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"certificate_arn": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"default_action": {
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
							DiffSuppressFunc: suppressIfDefaultActionTypeNot("forward"),
						},

						"redirect": {
							Type:             schema.TypeList,
							Optional:         true,
							DiffSuppressFunc: suppressIfDefaultActionTypeNot("redirect"),
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
							DiffSuppressFunc: suppressIfDefaultActionTypeNot("fixed-response"),
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
							DiffSuppressFunc: suppressIfDefaultActionTypeNot("authenticate-cognito"),
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
							DiffSuppressFunc: suppressIfDefaultActionTypeNot("authenticate-oidc"),
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
		},
	}
}

func resourceElbtoalbLbListenerCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("in lb listener create")

	// Expand the "listener" set to aws-sdk-go compat []*elb.Listener
	listeners, err := expandListeners(d.Get("listener").(*schema.Set).List())
	if err != nil {
		return err
	}

	for _, listener := range listeners {
		log.Println(listener)

		lbPort := *listener.LoadBalancerPort
		lbProtocol := strings.ToUpper(*listener.Protocol)
		instancePort := *listener.InstancePort

		lbSSL := ""

		if (strings.ToUpper(*listener.Protocol) == elbv2.ProtocolEnumHttps || strings.ToUpper(*listener.Protocol) == elbv2.ProtocolEnumTls) && *listener.SSLCertificateId != "" {
			lbProtocol = strings.ToUpper(*listener.Protocol)
			lbSSL = "ELBSecurityPolicy-2016-08"
		}

		var listenerName string
		var targetGroupArn string
		if v, ok := d.GetOk("name"); ok {
			listenerName = "listener-" + strconv.FormatInt(lbPort, 10)

			targetGroupArn = "aws_lb_target_group." + strings.Replace(v.(string), "elb-", "tg-", 1) + "-" + strconv.FormatInt(instancePort, 10) + ".arn"
		}

		targetGroupArn = strings.ReplaceAll(targetGroupArn, "-e2a-env-br", "")

		lbArn := "aws_lb.nlb.arn"
		if strings.ToUpper(*listener.Protocol) == elbv2.ProtocolEnumHttp || strings.ToUpper(*listener.Protocol) == elbv2.ProtocolEnumHttps {
			lbArn = "aws_lb.alb.arn"
		}


		certificateArn := *listener.SSLCertificateId

		if !fileExists(fmt.Sprintf("./lb_terraform/listener/%s.tf", listenerName)) {

			err := os.MkdirAll("./lb_terraform/listener", 0755)
			if err != nil {
				return err
			}

			f, err := os.Create(fmt.Sprintf("./lb_terraform/listener/%s.tf", listenerName))
			if err != nil {
				return err
			}

			defer f.Close()

			w := bufio.NewWriter(f)
			_, err = w.WriteString(fmt.Sprintf("resource \"aws_lb_listener\" \"%s\" {\nload_balancer_arn = %s\nport = %d\nprotocol = \"%s\"\nssl_policy = \"%s\"\ncertificate_arn = \"%s\"\n\ndefault_action {\ntype = \"forward\"\ntarget_group_arn = %s\n}\n}", listenerName, lbArn, lbPort, lbProtocol, lbSSL, certificateArn, targetGroupArn))
			if err != nil {
				return err
			}

			w.Flush()
		}
	}

	return nil
}

func resourceElbtoalbLbListenerRead(d *schema.ResourceData, meta interface{}) error {
	log.Println("in read")

	return nil
}

func resourceElbtoalbLbListenerDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("in delete")

	return nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func suppressIfDefaultActionTypeNot(t string) schema.SchemaDiffSuppressFunc {
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
