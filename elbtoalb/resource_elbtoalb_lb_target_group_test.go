package elbtoalb

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func init() {

}

func TestLBTargetGroupCloudwatchSuffixFromARN(t *testing.T) {
	cases := []struct {
		name   string
		arn    *string
		suffix string
	}{
		{
			name:   "valid suffix",
			arn:    aws.String(`arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/my-targets/73e2d6bc24d8a067`),
			suffix: `targetgroup/my-targets/73e2d6bc24d8a067`,
		},
		{
			name:   "no suffix",
			arn:    aws.String(`arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup`),
			suffix: ``,
		},
		{
			name:   "nil ARN",
			arn:    nil,
			suffix: ``,
		},
	}

	for _, tc := range cases {
		actual := lbTargetGroupSuffixFromARN(tc.arn)
		if actual != tc.suffix {
			t.Fatalf("bad suffix: %q\nExpected: %s\n     Got: %s", tc.name, tc.suffix, actual)
		}
	}
}

func testAccCheckAWSLBTargetGroupHealthCheckEnabled(res *elbv2.TargetGroup, expected bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if res.HealthCheckEnabled == nil {
			return fmt.Errorf("Expected HealthCheckEnabled to be %t, given %#v",
				expected, res.HealthCheckEnabled)
		}
		if *res.HealthCheckEnabled != expected {
			return fmt.Errorf("Expected HealthCheckEnabled to be %t, given %t",
				expected, *res.HealthCheckEnabled)
		}
		return nil
	}
}

func testAccCheckAWSLBTargetGroupHealthCheckInterval(res *elbv2.TargetGroup, expected int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if res.HealthCheckIntervalSeconds == nil {
			return fmt.Errorf("Expected HealthCheckIntervalSeconds to be %d, given: %#v",
				expected, res.HealthCheckIntervalSeconds)
		}
		if *res.HealthCheckIntervalSeconds != expected {
			return fmt.Errorf("Expected HealthCheckIntervalSeconds to be %d, given: %d",
				expected, *res.HealthCheckIntervalSeconds)
		}
		return nil
	}
}

func testAccCheckAWSLBTargetGroupHealthCheckTimeout(res *elbv2.TargetGroup, expected int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if res.HealthCheckTimeoutSeconds == nil {
			return fmt.Errorf("Expected HealthCheckTimeoutSeconds to be %d, given: %#v",
				expected, res.HealthCheckTimeoutSeconds)
		}
		if *res.HealthCheckTimeoutSeconds != expected {
			return fmt.Errorf("Expected HealthCheckTimeoutSeconds to be %d, given: %d",
				expected, *res.HealthCheckTimeoutSeconds)
		}
		return nil
	}
}

func testAccCheckAWSLBTargetGroupHealthyThreshold(res *elbv2.TargetGroup, expected int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if res.HealthyThresholdCount == nil {
			return fmt.Errorf("Expected HealthyThresholdCount to be %d, given: %#v",
				expected, res.HealthyThresholdCount)
		}
		if *res.HealthyThresholdCount != expected {
			return fmt.Errorf("Expected HealthyThresholdCount to be %d, given: %d",
				expected, *res.HealthyThresholdCount)
		}
		return nil
	}
}

func testAccCheckAWSLBTargetGroupUnhealthyThreshold(res *elbv2.TargetGroup, expected int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if res.UnhealthyThresholdCount == nil {
			return fmt.Errorf("Expected.UnhealthyThresholdCount to be %d, given: %#v",
				expected, res.UnhealthyThresholdCount)
		}
		if *res.UnhealthyThresholdCount != expected {
			return fmt.Errorf("Expected.UnhealthyThresholdCount to be %d, given: %d",
				expected, *res.UnhealthyThresholdCount)
		}
		return nil
	}
}

func testAccALB_defaults(name string) string {
	return fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 443
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  # HTTP Only
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    interval = 10
    port     = 8081
    protocol = "HTTP"
    healthy_threshold = 3
    unhealthy_threshold = 3
  }
  tags = {
    Name ="TestAccAWSLBTargetGroup_application_LB_defaults"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-alb-defaults"
  }
}`, name)
}

func testAccNLB_defaults(name, healthCheckBlock string) string {
	return fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 443
  protocol = "TCP"
  vpc_id   = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  health_check {
                %s
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_application_LB_defaults"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-nlb-defaults"
  }
}`, name, healthCheckBlock)
}

func testAccAWSLBTargetGroupConfig_basic(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-basic"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfigTags1(targetGroupName, tagKey1, tagValue1 string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = %[1]q
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    %[2]q = %[3]q
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = %[1]q
  }
}`, targetGroupName, tagKey1, tagValue1)
}

func testAccAWSLBTargetGroupConfigTags2(targetGroupName, tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = %[1]q
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    %[2]q = %[3]q
    %[4]q = %[5]q
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = %[1]q
  }
}`, targetGroupName, tagKey1, tagValue1, tagKey2, tagValue2)
}

func testAccAWSLBTargetGroupConfig_basicUdp(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 514
  protocol = "UDP"
  vpc_id = "${aws_vpc.test.id}"

  health_check {
    protocol = "TCP"
	port = 514
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-basic"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_withoutHealthcheck(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  target_type = "lambda"
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfigBackwardsCompatibility(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_alb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200
  slow_start = 0

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-bc"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_enableHealthcheck(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  target_type = "lambda"

  health_check {
    path = "/health"
    interval = 60
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_updatedPort(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 442
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-basic"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_updatedProtocol(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTP"
  vpc_id = "${aws_vpc.test2.id}"

  deregistration_delay = 200

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test2" {
  cidr_block = "10.10.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-basic-2"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-basic"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_updatedVpc(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health"
    interval = 60
    port = 8081
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 3
    unhealthy_threshold = 3
    matcher = "200-299"
  }

  tags = {
    Name ="TestAccAWSLBTargetGroup_basic"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-updated-vpc"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_updateHealthCheck(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  stickiness {
    type = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path = "/health2"
    interval = 30
    port = 8082
    protocol = "HTTPS"
    timeout = 4
    healthy_threshold = 4
    unhealthy_threshold = 4
    matcher = "200"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-update-health-check"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_Protocol_Tls(targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "tf-acc-test-lb-target-group-protocol-tls"
  }
}

resource "aws_lb_target_group" "test" {
  name     = %q
  port     = 443
  protocol = "TLS"
  vpc_id   = "${aws_vpc.test.id}"

  health_check {
    interval            = 10
    port                = "traffic-port"
    protocol            = "TCP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name ="tf-acc-test-lb-target-group-protocol-tls"
  }
}
`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCP(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 8082
  protocol = "TCP"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  health_check {
    interval = 10
    port = "traffic-port"
    protocol = "TCP"
    healthy_threshold = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name ="TestAcc_networkLB_TargetGroup"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCP_withProxyProtocol(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 8082
  protocol = "TCP"
  vpc_id = "${aws_vpc.test.id}"

	proxy_protocol_v2 = "true"
	deregistration_delay = 200

  health_check {
    interval = 10
    port = "traffic-port"
    protocol = "TCP"
    healthy_threshold = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name ="TestAcc_networkLB_TargetGroup"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCPInvalidThreshold(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 8082
  protocol = "TCP"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  health_check {
    interval = 10
    port = "traffic-port"
    protocol = "TCP"
    healthy_threshold = 3
    unhealthy_threshold = 4
  }

  tags = {
    Name ="TestAcc_networkLB_TargetGroup"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCPThresholdUpdated(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 8082
  protocol = "TCP"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  health_check {
    interval = 10
    port = "traffic-port"
    protocol = "TCP"
    healthy_threshold = 5
    unhealthy_threshold = 5
  }

  tags = {
    Name ="TestAcc_networkLB_TargetGroup"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp-threshold-updated"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCPIntervalUpdated(targetGroupName string) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 8082
  protocol = "TCP"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  health_check {
    interval = 30
    port = "traffic-port"
    protocol = "TCP"
    healthy_threshold = 5
    unhealthy_threshold = 5
  }

  tags = {
    Name ="TestAcc_networkLB_TargetGroup"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp-interval-updated"
  }
}`, targetGroupName)
}

func testAccAWSLBTargetGroupConfig_typeTCP_HTTPHealthCheck(targetGroupName, path string, threshold int) string {
	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name     = "%[1]s"
  port     = 8082
  protocol = "TCP"
  vpc_id   = "${aws_vpc.test.id}"

  health_check {
    healthy_threshold   = %[2]d
    unhealthy_threshold = %[2]d
    timeout             = "10"
    port                = "443"
    path                = "%[3]s"
    protocol            = "HTTPS"
    interval            = 30
    matcher             = "200-399"
  }

  tags = {
    Name ="TestAcc_networkLB_HTTPHealthCheck"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "terraform-testacc-lb-target-group-type-tcp-http-health-check"
  }
}`, targetGroupName, threshold, path)
}

func testAccAWSLBTargetGroupConfig_stickiness(targetGroupName string, addStickinessBlock bool, enabled bool) string {
	var stickinessBlock string

	if addStickinessBlock {
		stickinessBlock = fmt.Sprintf(`stickiness {
	    enabled = "%t"
	    type = "lb_cookie"
	    cookie_duration = 10000
	  }`, enabled)
	}

	return fmt.Sprintf(`resource "aws_lb_target_group" "test" {
  name = "%s"
  port = 443
  protocol = "HTTPS"
  vpc_id = "${aws_vpc.test.id}"

  deregistration_delay = 200

  %s

  health_check {
    path = "/health2"
    interval = 30
    port = 8082
    protocol = "HTTPS"
    timeout = 4
    healthy_threshold = 4
    unhealthy_threshold = 4
    matcher = "200"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-target-group-stickiness"
  }
}`, targetGroupName, stickinessBlock)
}

const testAccAWSLBTargetGroupConfig_namePrefix = `
resource "aws_lb_target_group" "test" {
  name_prefix = "tf-"
  port = 80
  protocol = "HTTP"
  vpc_id = "${aws_vpc.test.id}"
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
	tags = {
		Name = "terraform-testacc-lb-target-group-name-prefix"
	}
}
`

const testAccAWSLBTargetGroupConfig_generatedName = `
resource "aws_lb_target_group" "test" {
  port = 80
  protocol = "HTTP"
  vpc_id = "${aws_vpc.test.id}"
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
	tags = {
		Name = "terraform-testacc-lb-target-group-generated-name"
	}
}
`

func testAccAWSLBTargetGroupConfig_stickinessWithTCP(enabled bool) string {
	return fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name_prefix = "tf-"
  port        = 25
  protocol    = "TCP"
  vpc_id      = "${aws_vpc.test.id}"

  stickiness {
    type    = "lb_cookie"
    enabled = %t
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "testAccAWSLBTargetGroupConfig_namePrefix"
  }
}
`, enabled)
}
