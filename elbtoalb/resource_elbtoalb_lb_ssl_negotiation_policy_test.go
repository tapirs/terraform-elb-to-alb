package elbtoalb

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/elb"

)

func policyAttributesToMap(attributes *[]*elb.PolicyAttributeDescription) map[string]string {
	attrmap := make(map[string]string)

	for _, attrdef := range *attributes {
		attrmap[*attrdef.AttributeName] = *attrdef.AttributeValue
	}

	return attrmap
}

// Sets the SSL Negotiation policy with attributes.
func testAccSslNegotiationPolicyConfig(rName, key, certificate string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_iam_server_certificate" "test" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_elb" "test" {
  name               = "%[1]s"
  availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

  listener {
    instance_port      = 8000
    instance_protocol  = "https"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "${aws_iam_server_certificate.test.arn}"
  }
}

resource "aws_lb_ssl_negotiation_policy" "test" {
  name          = "foo-policy"
  load_balancer = "${aws_elb.test.id}"
  lb_port       = 443

  attribute {
    name  = "Protocol-TLSv1"
    value = "false"
  }

  attribute {
    name  = "Protocol-TLSv1.1"
    value = "false"
  }

  attribute {
    name  = "Protocol-TLSv1.2"
    value = "true"
  }

  attribute {
    name  = "Server-Defined-Cipher-Order"
    value = "true"
  }

  attribute {
    name  = "ECDHE-RSA-AES128-GCM-SHA256"
    value = "true"
  }

  attribute {
    name  = "AES128-GCM-SHA256"
    value = "true"
  }

  attribute {
    name  = "EDH-RSA-DES-CBC3-SHA"
    value = "false"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}
