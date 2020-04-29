package elbtoalb

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestLBListenerARNFromRuleARN(t *testing.T) {
	cases := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "valid listener rule arn",
			arn:      "arn:aws:elasticloadbalancing:us-east-1:012345678912:listener-rule/app/name/0123456789abcdef/abcdef0123456789/456789abcedf1234",
			expected: "arn:aws:elasticloadbalancing:us-east-1:012345678912:listener/app/name/0123456789abcdef/abcdef0123456789",
		},
		{
			name:     "listener arn",
			arn:      "arn:aws:elasticloadbalancing:us-east-1:012345678912:listener/app/name/0123456789abcdef/abcdef0123456789",
			expected: "",
		},
		{
			name:     "some other arn",
			arn:      "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/my-targets/73e2d6bc24d8a067",
			expected: "",
		},
		{
			name:     "not an arn",
			arn:      "blah blah blah",
			expected: "",
		},
		{
			name:     "empty arn",
			arn:      "",
			expected: "",
		},
	}

	for _, tc := range cases {
		actual := lbListenerARNFromRuleARN(tc.arn)
		if actual != tc.expected {
			t.Fatalf("incorrect arn returned: %q\nExpected: %s\n     Got: %s", tc.name, tc.expected, actual)
		}
	}
}

func testAccCheckAWSLbListenerRuleRecreated(t *testing.T,
	before, after *elbv2.Rule) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if *before.RuleArn == *after.RuleArn {
			t.Fatalf("Expected change of Listener Rule ARNs, but both were %v", before.RuleArn)
		}
		return nil
	}
}

func testAccAWSLBListenerRuleConfig_multipleConditions(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*", "static"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-multiple-conditions"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-multiple-conditions-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfig_basic(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-basic-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfigBackwardsCompatibility(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_alb_listener_rule" "static" {
  listener_arn = "${aws_alb_listener.front_end.arn}"
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = "${aws_alb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_alb_listener" "front_end" {
  load_balancer_arn = "${aws_alb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_alb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_alb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_alb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-bc"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-bc-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfig_redirect(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_redirect"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-redirect"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-redirect-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_redirect"
  }
}
`, lbName)
}

func testAccAWSLBListenerRuleConfig_fixedResponse(lbName, response string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "%s"
      status_code  = "200"
    }
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Fixed response content"
      status_code  = "200"
    }
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_fixedResponse"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-fixedresponse"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-fixedresponse-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_fixedresponse"
  }
}
`, response, lbName)
}

func testAccAWSLBListenerRuleConfig_updateRulePriority(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 101

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-update-rule-priority"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-update-rule-priority-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfig_changeRuleArn(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end_ruleupdate.arn}"
  priority     = 101

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb_listener" "front_end_ruleupdate" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "8080"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-change-rule-arn"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-change-rule-arn-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfig_priorityBase(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-priority"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-priority-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerRuleConfig_priorityFirst(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priorityBase(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "first" {
  listener_arn = "${aws_lb_listener.front_end.arn}"

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/first/*"]
  }
}

resource "aws_lb_listener_rule" "third" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority = 3

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/third/*"]
  }

  depends_on = ["aws_lb_listener_rule.first"]
}
`)
}

func testAccAWSLBListenerRuleConfig_priorityLast(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priorityFirst(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "last" {
  listener_arn = "${aws_lb_listener.front_end.arn}"

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/last/*"]
  }
}
`)
}

func testAccAWSLBListenerRuleConfig_priorityStatic(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priorityFirst(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "last" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority = 7

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/last/*"]
  }
}
`)
}

func testAccAWSLBListenerRuleConfig_priorityParallelism(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priorityStatic(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "parallelism" {
  count = 10

  listener_arn = "${aws_lb_listener.front_end.arn}"

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/${count.index}/*"]
  }
}
`)
}

func testAccAWSLBListenerRuleConfig_priority50000(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priorityBase(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "priority50000" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 50000

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/50000/*"]
  }
}
`)
}

// priority out of range (1, 50000)
func testAccAWSLBListenerRuleConfig_priority50001(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priority50000(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "priority50001" {
  listener_arn = "${aws_lb_listener.front_end.arn}"

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/50001/*"]
  }
}
`)
}

func testAccAWSLBListenerRuleConfig_priorityInUse(lbName, targetGroupName string) string {
	return testAccAWSLBListenerRuleConfig_priority50000(lbName, targetGroupName) + fmt.Sprintf(`
resource "aws_lb_listener_rule" "priority50000_in_use" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 50000

  action {
    type = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field = "path-pattern"
    values = ["/50000_in_use/*"]
  }
}
`)
}

func testAccAWSLBListenerRuleConfig_cognito(rName, key, certificate string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "cognito" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      user_pool_arn       = "${aws_cognito_user_pool.test.arn}"
      user_pool_client_id = "${aws_cognito_user_pool_client.test.id}"
      user_pool_domain    = "${aws_cognito_user_pool_domain.test.domain}"

      authentication_request_extra_params = {
        param = "test"
      }
    }
  }

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_iam_server_certificate" "test" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%[1]s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_cognito"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%[1]s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-cognito"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-cognito-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_cognito"
  }
}

resource "aws_cognito_user_pool" "test" {
  name = "%[1]s-pool"
}

resource "aws_cognito_user_pool_client" "test" {
  name                                 = "%[1]s-pool-client"
  user_pool_id                         = "${aws_cognito_user_pool.test.id}"
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code", "implicit"]
  allowed_oauth_scopes                 = ["phone", "email", "openid", "profile", "aws.cognito.signin.user.admin"]
  callback_urls                        = ["https://www.example.com/callback", "https://www.example.com/redirect"]
  default_redirect_uri                 = "https://www.example.com/redirect"
  logout_urls                          = ["https://www.example.com/login"]
}

resource "aws_cognito_user_pool_domain" "test" {
  domain       = "%[1]s-pool-domain"
  user_pool_id = "${aws_cognito_user_pool.test.id}"
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerRuleConfig_oidc(rName, key, certificate string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "oidc" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type = "authenticate-oidc"

    authenticate_oidc {
      authorization_endpoint = "https://example.com/authorization_endpoint"
      client_id              = "s6BhdRkqt3"
      client_secret          = "7Fjfp0ZBr1KtDRbnfVdmIw"
      issuer                 = "https://example.com"
      token_endpoint         = "https://example.com/token_endpoint"
      user_info_endpoint     = "https://example.com/user_info_endpoint"

      authentication_request_extra_params = {
        param = "test"
      }
    }
  }

  action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_iam_server_certificate" "test" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%[1]s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_cognito"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%[1]s"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-listener-rule-cognito"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-rule-cognito-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_cognito"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerRuleConfig_Action_Order(rName, key, certificate string) string {
	return fmt.Sprintf(`
variable "rName" {
  default = %[1]q
}

data "aws_availability_zones" "available" {}

resource "aws_lb_listener_rule" "test" {
  listener_arn = "${aws_lb_listener.test.arn}"

  action {
    order = 1
    type  = "authenticate-oidc"

    authenticate_oidc {
      authorization_endpoint = "https://example.com/authorization_endpoint"
      client_id              = "s6BhdRkqt3"
      client_secret          = "7Fjfp0ZBr1KtDRbnfVdmIw"
      issuer                 = "https://example.com"
      token_endpoint         = "https://example.com/token_endpoint"
      user_info_endpoint     = "https://example.com/user_info_endpoint"

      authentication_request_extra_params = {
        param = "test"
      }
    }
  }

  action {
    order            = 2
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }

  condition {
    field  = "path-pattern"
    values = ["/static/*"]
  }
}

resource "aws_iam_server_certificate" "test" {
  certificate_body = "%[2]s"
  name             = "${var.rName}"
  private_key      = "%[3]s"
}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "test" {
  internal        = true
  name            = "${var.rName}"
  security_groups = ["${aws_security_group.test.id}"]
  subnets         = ["${aws_subnet.test.*.id[0]}", "${aws_subnet.test.*.id[1]}"]
}

resource "aws_lb_target_group" "test" {
  name     = "${var.rName}"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.test.id}"

  health_check {
    path                = "/health"
    interval            = 60
    port                = 8081
    protocol            = "HTTP"
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "${var.rName}"
  }
}

resource "aws_subnet" "test" {
  count = 2

  availability_zone       = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block              = "10.0.${count.index}.0/24"
  map_public_ip_on_launch = true
  vpc_id                  = "${aws_vpc.test.id}"

  tags = {
    Name = "${var.rName}"
  }
}

resource "aws_security_group" "test" {
  name   = "${var.rName}"
  vpc_id = "${aws_vpc.test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.rName}"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerRuleConfig_condition_error(condition string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "error" {
  listener_arn = "arn:aws:elasticloadbalancing:us-west-2:111111111111:listener/app/example/1234567890abcdef/1234567890abcdef"
  priority     = 100

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Static"
      status_code  = 200
    }
  }

  %s
}
`, condition)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_empty() string {
	return testAccAWSLBListenerRuleConfig_condition_error("condition {}")
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_field() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`condition { field = "host-header" }`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_values() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`condition { values = ["example.com"] }`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_http_header() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  http_header {
    http_header_name = "X-Clacks-Overhead"
    values           = ["GNU Terry Pratchett"]
  }
}`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_http_request_method() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  http_request_method {
    values = ["POST"]
  }
}`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_path_pattern() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  path_pattern {
    values = ["/"]
  }
}`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_query_string() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  query_string {
    key   = "foo"
    value = "bar"
  }
}`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_source_ip() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  source_ip {
    values = ["192.168.0.0/16"]
  }
}`)
}

func testAccAWSLBListenerRuleConfig_conditionAttributesCount_classic() string {
	return testAccAWSLBListenerRuleConfig_condition_error(`
condition {
  host_header {
    values = ["example.com"]
  }
  field  = "host-header"
  values = ["example2.com"]
}`)
}

func testAccAWSLBListenerRuleConfig_condition_base(condition, name, lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener_rule" "static" {
  listener_arn = "${aws_lb_listener.front_end.arn}"
  priority     = 100

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Static"
      status_code  = 200
    }
  }

  %s
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = 404
    }
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_condition%s"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "TestAccAWSALB_condition%s"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "TestAccAWSALB_condition%s-${count.index}"
  }
}

resource "aws_security_group" "alb_test" {
  name        = "allow_all_alb_test"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_condition%s"
  }
}
`, condition, lbName, name, name, name, name)
}

func testAccAWSLBListenerRuleConfig_conditionHostHeader(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  host_header {
    values = ["example.com", "www.example.com"]
  }
}
`, "HostHeader", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionHostHeader_deprecated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field  = "host-header"
  values = ["example.com"]
}
`, "HostHeaderDep", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionHttpHeader(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  http_header {
    http_header_name = "X-Forwarded-For"
    values           = ["192.168.1.*", "10.0.0.*"]
  }
}

condition {
  http_header {
    http_header_name = "Zz9~|_^.-+*'&%$#!0aA"
    values           = ["RFC7230 Validity"]
  }
}
`, "HttpHeader", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionHttpHeader_invalid() string {
	return `
resource "aws_lb_listener_rule" "static" {
  listener_arn = "arn:aws:elasticloadbalancing:us-west-2:111111111111:listener/app/test/xxxxxxxxxxxxxxxx/xxxxxxxxxxxxxxxx"
  priority     = 100

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Static"
      status_code  = 200
    }
  }

  condition {
    http_header {
      http_header_name = "Invalid@"
      values           = ["RFC7230 Validity"]
    }
  }
}
`
}

func testAccAWSLBListenerRuleConfig_conditionHttpRequestMethod(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  http_request_method {
    values = ["GET", "POST"]
  }
}
`, "HttpRequestMethod", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionPathPattern(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  path_pattern {
    values = ["/public/*", "/cgi-bin/*"]
  }
}
`, "PathPattern", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionPathPattern_deprecated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field = "path-pattern"
  values = ["/public/*"]
}
`, "PathPattern", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionPathPattern_deprecatedUpdated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field = "path-pattern"
  values = ["/cgi-bin/*"]
}
`, "PathPattern", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionPathPattern_migrated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  path_pattern {
    values = ["/cgi-bin/*"]
  }
}
`, "PathPattern", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionQueryString(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  query_string {
    value = "surprise"
  }
  query_string {
    key   = ""
    value = "blank"
  }
}

condition {
  query_string {
    key   = "foo"
    value = "bar"
  }
  query_string {
    key   = "foo"
    value = "baz"
  }
}
`, "QueryString", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionSourceIp(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  source_ip {
    values = [
      "192.168.0.0/16",
      "dead:cafe::/64",
    ]
  }
}
`, "SourceIp", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionMixed(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field  = "path-pattern"
  values = ["/public/*"]
}

condition {
  source_ip {
    values = [
      "192.168.0.0/16",
    ]
  }
}
`, "Mixed", lbName)
}

// Update new style condition without modifying deprecated. Issue GH-11323
func testAccAWSLBListenerRuleConfig_conditionMixed_updated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field  = "path-pattern"
  values = ["/public/*"]
}

condition {
  source_ip {
    values = [
      "dead:cafe::/64",
    ]
  }
}
`, "Mixed", lbName)
}

// Then update deprecated syntax without touching new. Issue GH-11362
func testAccAWSLBListenerRuleConfig_conditionMixed_updated2(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  field  = "path-pattern"
  values = ["/cgi-bin/*"]
}

condition {
  source_ip {
    values = [
      "dead:cafe::/64",
    ]
  }
}
`, "Mixed", lbName)
}

// Currently a maximum of 5 condition values per rule
func testAccAWSLBListenerRuleConfig_conditionMultiple(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  host_header {
    values = ["example.com"]
  }
}

condition {
  http_header {
    http_header_name = "X-Forwarded-For"
    values           = ["192.168.1.*"]
  }
}

condition {
  http_request_method {
    values = ["GET"]
  }
}

condition {
  path_pattern {
    values = ["/public/*"]
  }
}

condition {
  source_ip {
    values = ["192.168.0.0/16"]
  }
}
`, "Multiple", lbName)
}

func testAccAWSLBListenerRuleConfig_conditionMultiple_updated(lbName string) string {
	return testAccAWSLBListenerRuleConfig_condition_base(`
condition {
  host_header {
    values = ["foobar.com"]
  }
}

condition {
  http_header {
    http_header_name = "X-Forwarded-For"
    values           = ["192.168.2.*"]
  }
}

condition {
  http_request_method {
    values = ["POST"]
  }
}

condition {
  path_pattern {
    values = ["/public/2/*"]
  }
}

condition {
  source_ip {
    values = ["192.168.0.0/24"]
  }
}
`, "Multiple", lbName)
}
