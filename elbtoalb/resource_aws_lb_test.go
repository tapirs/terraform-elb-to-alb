package elbtoalb

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func init() {

}

func TestLBCloudwatchSuffixFromARN(t *testing.T) {
	cases := []struct {
		name   string
		arn    *string
		suffix string
	}{
		{
			name:   "valid suffix",
			arn:    aws.String(`arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-alb/abc123`),
			suffix: `app/my-alb/abc123`,
		},
		{
			name:   "no suffix",
			arn:    aws.String(`arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer`),
			suffix: ``,
		},
		{
			name:   "nil ARN",
			arn:    nil,
			suffix: ``,
		},
	}

	for _, tc := range cases {
		actual := lbSuffixFromARN(tc.arn)
		if actual != tc.suffix {
			t.Fatalf("bad suffix: %q\nExpected: %s\n     Got: %s", tc.name, tc.suffix, actual)
		}
	}
}

func testAccCheckAWSlbARNs(pre, post *elbv2.LoadBalancer) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if aws.StringValue(pre.LoadBalancerArn) != aws.StringValue(post.LoadBalancerArn) {
			return errors.New("LB has been recreated. ARNs are different")
		}

		return nil
	}
}

func testAccAWSLBConfigWithIpAddressTypeUpdated(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test_1.id}", "${aws_subnet.alb_test_2.id}"]

  ip_address_type = "dualstack"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.lb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  deregistration_delay = 200

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path                = "/health2"
    interval            = 30
    port                = 8082
    protocol            = "HTTPS"
    timeout             = 4
    healthy_threshold   = 4
    unhealthy_threshold = 4
    matcher             = "200"
  }
}

resource "aws_egress_only_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.alb_test.id}"
}

resource "aws_vpc" "alb_test" {
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name = "terraform-testacc-lb-with-ip-address-type-updated"
  }
}

resource "aws_internet_gateway" "foo" {
  vpc_id = "${aws_vpc.alb_test.id}"
}

resource "aws_subnet" "alb_test_1" {
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2a"
  ipv6_cidr_block         = "${cidrsubnet(aws_vpc.alb_test.ipv6_cidr_block, 8, 1)}"

  tags = {
    Name = "tf-acc-lb-with-ip-address-type-updated-1"
  }
}

resource "aws_subnet" "alb_test_2" {
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2b"
  ipv6_cidr_block         = "${cidrsubnet(aws_vpc.alb_test.ipv6_cidr_block, 8, 2)}"

  tags = {
    Name = "tf-acc-lb-with-ip-address-type-updated-2"
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

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, lbName)
}

func testAccAWSLBConfigWithIpAddressType(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test_1.id}", "${aws_subnet.alb_test_2.id}"]

  ip_address_type = "ipv4"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.lb_test.id}"
  protocol          = "HTTP"
  port              = "80"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  deregistration_delay = 200

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 10000
  }

  health_check {
    path                = "/health2"
    interval            = 30
    port                = 8082
    protocol            = "HTTPS"
    timeout             = 4
    healthy_threshold   = 4
    unhealthy_threshold = 4
    matcher             = "200"
  }
}

resource "aws_egress_only_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.alb_test.id}"
}

resource "aws_vpc" "alb_test" {
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name = "terraform-testacc-lb-with-ip-address-type"
  }
}

resource "aws_internet_gateway" "foo" {
  vpc_id = "${aws_vpc.alb_test.id}"
}

resource "aws_subnet" "alb_test_1" {
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2a"
  ipv6_cidr_block         = "${cidrsubnet(aws_vpc.alb_test.ipv6_cidr_block, 8, 1)}"

  tags = {
    Name = "tf-acc-lb-with-ip-address-type-1"
  }
}

resource "aws_subnet" "alb_test_2" {
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2b"
  ipv6_cidr_block         = "${cidrsubnet(aws_vpc.alb_test.ipv6_cidr_block, 8, 2)}"

  tags = {
    Name = "tf-acc-lb-with-ip-address-type-2"
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

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}
`, lbName, lbName)
}

func testAccAWSLBConfig_basic(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-basic"
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
`, lbName)
}

func testAccAWSLBConfig_enableHttp2(lbName string, http2 bool) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  enable_http2 = %t

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-basic-${count.index}"
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
`, lbName, http2)
}

func testAccAWSLBConfig_enableDropInvalidHeaderFields(lbName string, dropInvalid bool) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  drop_invalid_header_fields = %t

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-basic-${count.index}"
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
`, lbName, dropInvalid)
}

func testAccAWSLBConfig_enableDeletionProtection(lbName string, deletion_protection bool) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = %t

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-basic-${count.index}"
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
`, lbName, deletion_protection)
}

func testAccAWSLBConfig_networkLoadbalancer_subnets(lbName string) string {
	return fmt.Sprintf(`
resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-network-load-balancer-subnets"
  }
}

resource "aws_lb" "lb_test" {
  name = "%s"

  subnets = [
    "${aws_subnet.alb_test_1.id}",
    "${aws_subnet.alb_test_2.id}",
    "${aws_subnet.alb_test_3.id}",
  ]

  load_balancer_type               = "network"
  internal                         = true
  idle_timeout                     = 60
  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = false

  tags = {
    Name = "testAccAWSLBConfig_networkLoadbalancer_subnets"
  }
}

resource "aws_subnet" "alb_test_1" {
  vpc_id            = "${aws_vpc.alb_test.id}"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "tf-acc-lb-network-load-balancer-subnets-1"
  }
}

resource "aws_subnet" "alb_test_2" {
  vpc_id            = "${aws_vpc.alb_test.id}"
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "tf-acc-lb-network-load-balancer-subnets-2"
  }
}

resource "aws_subnet" "alb_test_3" {
  vpc_id            = "${aws_vpc.alb_test.id}"
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-west-2c"

  tags = {
    Name = "tf-acc-lb-network-load-balancer-subnets-3"
  }
}
`, lbName)
}

func testAccAWSLBConfig_networkLoadbalancer(lbName string, cz bool) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name               = "%s"
  internal           = true
  load_balancer_type = "network"

  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = %t

  subnet_mapping {
    subnet_id = "${aws_subnet.alb_test.id}"
  }

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.10.0.0/16"

  tags = {
    Name = "terraform-testacc-network-load-balancer"
  }
}

resource "aws_subnet" "alb_test" {
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "10.10.0.0/21"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2a"

  tags = {
    Name = "tf-acc-network-load-balancer"
  }
}
`, lbName, cz)
}

func testAccAWSLBConfig_networkLoadBalancerEIP(lbName string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

resource "aws_vpc" "main" {
  cidr_block = "10.10.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-network-load-balancer-eip"
  }
}

resource "aws_subnet" "public" {
  count             = "${length(data.aws_availability_zones.available.names)}"
  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block        = "10.10.${count.index}.0/24"
  vpc_id            = "${aws_vpc.main.id}"

  tags = {
    Name = "tf-acc-lb-network-load-balancer-eip-${count.index}"
  }
}

resource "aws_internet_gateway" "default" {
  vpc_id = "${aws_vpc.main.id}"
}

resource "aws_route_table" "public" {
  vpc_id = "${aws_vpc.main.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.default.id}"
  }
}

resource "aws_route_table_association" "a" {
  count          = "${length(data.aws_availability_zones.available.names)}"
  subnet_id      = "${aws_subnet.public.*.id[count.index]}"
  route_table_id = "${aws_route_table.public.id}"
}

resource "aws_lb" "lb_test" {
  name               = "%s"
  load_balancer_type = "network"

  subnet_mapping {
    subnet_id     = "${aws_subnet.public.0.id}"
    allocation_id = "${aws_eip.lb.0.id}"
  }

  subnet_mapping {
    subnet_id     = "${aws_subnet.public.1.id}"
    allocation_id = "${aws_eip.lb.1.id}"
  }

  depends_on = ["aws_internet_gateway.default"]
}

resource "aws_eip" "lb" {
  count = "2"
}
`, lbName)
}

func testAccAWSLBConfigBackwardsCompatibility(lbName string) string {
	return fmt.Sprintf(`
resource "aws_alb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-bc"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-bc-${count.index}"
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
`, lbName)
}

func testAccAWSLBConfig_updateSubnets(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-update-subnets"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 3
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-update-subnets-${count.index}"
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
`, lbName)
}

func testAccAWSLBConfig_generatedName() string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-generated-name"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.alb_test.id}"

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-generated-name-${count.index}"
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
}`)
}

func testAccAWSLBConfig_zeroValueName() string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = ""
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

# See https://github.com/terraform-providers/terraform-provider-aws/issues/2498
output "lb_name" {
  value = "${aws_lb.lb_test.name}"
}

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "alb_test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-zero-value-name"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.alb_test.id}"

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-zero-value-name-${count.index}"
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
}`)
}

func testAccAWSLBConfig_namePrefix() string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name_prefix     = "tf-lb-"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-name-prefix"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-name-prefix-${count.index}"
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
}`)
}
func testAccAWSLBConfig_updatedTags(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout = 30
  enable_deletion_protection = false

  tags = {
    Environment = "Production"
    Type = "Sample Type Tag"
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
    Name = "terraform-testacc-lb-updated-tags"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-updated-tags-${count.index}"
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
`, lbName)
}

func testAccAWSLBConfigALBAccessLogsBase(bucketName string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

data "aws_elb_service_account" "current" {}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-access-logs"
  }
}

resource "aws_subnet" "alb_test" {
  count = 2

  availability_zone = "${element(data.aws_availability_zones.available.names, count.index)}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.test.id}"

  tags = {
    Name = "tf-acc-lb-access-logs-${count.index}"
  }
}

resource "aws_s3_bucket" "test" {
  bucket        = %[1]q
  force_destroy = true
}

data "aws_iam_policy_document" "test" {
  statement {
    actions   = ["s3:PutObject"]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.test.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${data.aws_elb_service_account.current.arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "test" {
  bucket = "${aws_s3_bucket.test.bucket}"
  policy = "${data.aws_iam_policy_document.test.json}"
}
`, bucketName)
}

func testAccAWSLBConfigALBAccessLogs(enabled bool, lbName, bucketName, bucketPrefix string) string {
	return testAccAWSLBConfigALBAccessLogsBase(bucketName) + fmt.Sprintf(`
resource "aws_lb" "test" {
  internal = true
  name     = %[1]q
  subnets  = "${aws_subnet.alb_test.*.id}"

  access_logs {
    bucket  = "${aws_s3_bucket_policy.test.bucket}"
    enabled = %[2]t
    prefix  = %[3]q
  }
}
`, lbName, enabled, bucketPrefix)
}

func testAccAWSLBConfigALBAccessLogsNoBlocks(lbName, bucketName string) string {
	return testAccAWSLBConfigALBAccessLogsBase(bucketName) + fmt.Sprintf(`
resource "aws_lb" "test" {
  internal = true
  name     = %[1]q
  subnets  = "${aws_subnet.alb_test.*.id}"
}
`, lbName)
}

func testAccAWSLBConfigNLBAccessLogsBase(bucketName string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

data "aws_elb_service_account" "current" {}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-testacc-lb-access-logs"
  }
}

resource "aws_subnet" "alb_test" {
  count = 2

  availability_zone = "${element(data.aws_availability_zones.available.names, count.index)}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.test.id}"

  tags = {
    Name = "tf-acc-lb-access-logs-${count.index}"
  }
}

resource "aws_s3_bucket" "test" {
  bucket        = %[1]q
  force_destroy = true
}

data "aws_iam_policy_document" "test" {
  statement {
    actions   = ["s3:PutObject"]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.test.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.test.arn}"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "test" {
  bucket = "${aws_s3_bucket.test.bucket}"
  policy = "${data.aws_iam_policy_document.test.json}"
}
`, bucketName)
}

func testAccAWSLBConfigNLBAccessLogs(enabled bool, lbName, bucketName, bucketPrefix string) string {
	return testAccAWSLBConfigNLBAccessLogsBase(bucketName) + fmt.Sprintf(`
resource "aws_lb" "test" {
  internal           = true
  load_balancer_type = "network"
  name               = %[1]q
  subnets            = "${aws_subnet.alb_test.*.id}"

  access_logs {
    bucket  = "${aws_s3_bucket_policy.test.bucket}"
    enabled = %[2]t
    prefix  = %[3]q
  }
}
`, lbName, enabled, bucketPrefix)
}

func testAccAWSLBConfigNLBAccessLogsNoBlocks(lbName, bucketName string) string {
	return testAccAWSLBConfigNLBAccessLogsBase(bucketName) + fmt.Sprintf(`
resource "aws_lb" "test" {
  internal           = true
  load_balancer_type = "network"
  name               = %[1]q
  subnets            = "${aws_subnet.alb_test.*.id}"
}
`, lbName)
}

func testAccAWSLBConfig_nosg(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name     = "%s"
  internal = true
  subnets  = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-no-sg"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-no-sg-${count.index}"
  }
}
`, lbName)
}

func testAccAWSLBConfig_updateSecurityGroups(lbName string) string {
	return fmt.Sprintf(`
resource "aws_lb" "lb_test" {
  name            = "%s"
  internal        = true
  security_groups = ["${aws_security_group.alb_test.id}", "${aws_security_group.alb_test_2.id}"]
  subnets         = "${aws_subnet.alb_test.*.id}"

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
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
    Name = "terraform-testacc-lb-update-security-groups"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-update-security-groups-${count.index}"
  }
}

resource "aws_security_group" "alb_test_2" {
  name        = "allow_all_alb_test_2"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.alb_test.id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "TestAccAWSALB_basic_2"
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
`, lbName)
}
