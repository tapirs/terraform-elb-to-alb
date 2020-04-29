package elbtoalb

import (
	"fmt"
)

func testAccAWSLBListenerConfig_basic(lbName, targetGroupName string) string {
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
    Name = "terraform-testacc-lb-listener-basic"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-basic-${count.index}"
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

func testAccAWSLBListenerConfig_basicUdp(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "UDP"
  port              = "514"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%s"
  internal        = false
  load_balancer_type = "network"
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }
}

resource "aws_lb_target_group" "test" {
  name     = "%s"
  port     = 514
  protocol = "UDP"
  vpc_id   = "${aws_vpc.alb_test.id}"

  health_check {
    port                = 514
    protocol            = "TCP"
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
    Name = "terraform-testacc-lb-listener-basic"
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
    Name = "tf-acc-lb-listener-basic-${count.index}"
  }
}
`, lbName, targetGroupName)
}

func testAccAWSLBListenerConfigBackwardsCompatibility(lbName, targetGroupName string) string {
	return fmt.Sprintf(`
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
    Name = "terraform-testacc-lb-listener-bc"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-bc-${count.index}"
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

func testAccAWSLBListenerConfig_https(rName, key, certificate string) string {
	return fmt.Sprintf(`
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.alb_test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test_cert.arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}

resource "aws_lb" "alb_test" {
  name            = "%[1]s"
  internal        = false
  security_groups = ["${aws_security_group.alb_test.id}"]
  subnets         = ["${aws_subnet.alb_test.*.id[0]}", "${aws_subnet.alb_test.*.id[1]}"]

  idle_timeout               = 30
  enable_deletion_protection = false

  tags = {
    Name = "TestAccAWSALB_basic"
  }

  depends_on = ["aws_internet_gateway.gw"]
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
    Name = "terraform-testacc-lb-listener-https"
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
    Name = "tf-acc-lb-listener-https-${count.index}"
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

resource "aws_iam_server_certificate" "test_cert" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerConfig_Protocol_Tls(rName, key, certificate string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "tf-acc-test-lb-listener-protocol-tls"
  }
}

resource "aws_subnet" "test" {
  count = 2

  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.test.id}"

  tags = {
    Name = "tf-acc-test-lb-listener-protocol-tls"
  }
}

resource "aws_lb" "test" {
  internal           = true
  load_balancer_type = "network"
  name               = %[1]q
  subnets            = ["${aws_subnet.test.*.id[0]}", "${aws_subnet.test.*.id[1]}"]

  tags = {
    Name = "tf-acc-test-lb-listener-protocol-tls"
  }
}

resource "aws_lb_target_group" "test" {
  name     = %[1]q
  port     = 443
  protocol = "TCP"
  vpc_id   = "${aws_vpc.test.id}"

  health_check {
    interval            = 10
    port                = "traffic-port"
    protocol            = "TCP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name = "tf-acc-test-lb-listener-protocol-tls"
  }
}

resource "aws_lb_listener" "test" {
  certificate_arn   = "${aws_acm_certificate.test.arn}"
  load_balancer_arn = "${aws_lb.test.arn}"
  port              = "443"
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"

  default_action {
    target_group_arn = "${aws_lb_target_group.test.arn}"
    type             = "forward"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerConfig_redirect(lbName string) string {
	return fmt.Sprintf(`
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
    Name = "terraform-testacc-lb-listener-redirect"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-redirect-${count.index}"
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

func testAccAWSLBListenerConfig_fixedResponse(lbName string) string {
	return fmt.Sprintf(`
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
    Name = "TestAccAWSALB_fixedresponse"
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
    Name = "terraform-testacc-lb-listener-fixedresponse"
  }
}

resource "aws_subnet" "alb_test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.alb_test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"

  tags = {
    Name = "tf-acc-lb-listener-fixedresponse-${count.index}"
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
`, lbName)
}

func testAccAWSLBListenerConfig_cognito(rName, key, certificate string) string {
	return fmt.Sprintf(`
resource "aws_lb" "test" {
  name                       = "%[1]s"
  internal                   = false
  security_groups            = ["${aws_security_group.test.id}"]
  subnets                    = ["${aws_subnet.test.*.id[0]}", "${aws_subnet.test.*.id[1]}"]
  enable_deletion_protection = false
}

resource "aws_lb_target_group" "test" {
  name     = "%[1]s"
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

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "test" {
  vpc_id = "${aws_vpc.test.id}"
}

resource "aws_subnet" "test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"
}

resource "aws_security_group" "test" {
  name        = "%[1]s"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.test.id}"

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
}

resource "aws_cognito_user_pool" "test" {
  name = "%[1]s"
}

resource "aws_cognito_user_pool_client" "test" {
  name                                 = "%[1]s"
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
  domain       = "%[1]s"
  user_pool_id = "${aws_cognito_user_pool.test.id}"
}

resource "aws_iam_server_certificate" "test" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
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

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerConfig_oidc(rName, key, certificate string) string {
	return fmt.Sprintf(`
resource "aws_lb" "test" {
  name                       = "%[1]s"
  internal                   = false
  security_groups            = ["${aws_security_group.test.id}"]
  subnets                    = ["${aws_subnet.test.*.id[0]}", "${aws_subnet.test.*.id[1]}"]
  enable_deletion_protection = false
}

resource "aws_lb_target_group" "test" {
  name     = "%[1]s"
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

variable "subnets" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = "list"
}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "test" {
  vpc_id = "${aws_vpc.test.id}"
}

resource "aws_subnet" "test" {
  count                   = 2
  vpc_id                  = "${aws_vpc.test.id}"
  cidr_block              = "${element(var.subnets, count.index)}"
  map_public_ip_on_launch = true
  availability_zone       = "${element(data.aws_availability_zones.available.names, count.index)}"
}

resource "aws_security_group" "test" {
  name        = "%[1]s"
  description = "Used for ALB Testing"
  vpc_id      = "${aws_vpc.test.id}"

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
}

resource "aws_iam_server_certificate" "test" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
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

  default_action {
    target_group_arn = "${aws_lb_target_group.test.id}"
    type             = "forward"
  }
}
`, rName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccAWSLBListenerConfig_DefaultAction_Order(rName, key, certificate string) string {
	return fmt.Sprintf(`
variable "rName" {
  default = %[1]q
}

data "aws_availability_zones" "available" {}

resource "aws_lb_listener" "test" {
  load_balancer_arn = "${aws_lb.test.id}"
  protocol          = "HTTPS"
  port              = "443"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.test.arn}"

  default_action {
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

  default_action {
    order            = 2
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.test.arn}"
  }
}

resource "aws_iam_server_certificate" "test" {
  certificate_body = "%[2]s"
  name             = "${var.rName}"
  private_key      = "%[3]s"
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
