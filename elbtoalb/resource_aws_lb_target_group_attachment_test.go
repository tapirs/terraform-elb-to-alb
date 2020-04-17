package elbtoalb

import (
	"fmt"
)

func testAccAWSLBTargetGroupAttachmentConfigInstanceBase() string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  # t2.micro instance type is not available in these Availability Zones
  blacklisted_zone_ids = ["usw2-az4"]
  state                = "available"
}

data "aws_ami" "amzn-ami-minimal-hvm-ebs" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-minimal-hvm-*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_instance" "test" {
  ami           = data.aws_ami.amzn-ami-minimal-hvm-ebs.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.test.id
}

resource "aws_subnet" "test" {
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "10.0.1.0/24"
  vpc_id            = aws_vpc.test.id

  tags = {
    Name = "tf-acc-test-lb-target-group-attachment"
  }
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "tf-acc-test-lb-target-group-attachment"
  }
}
`)
}

func testAccAWSLBTargetGroupAttachmentConfigTargetIdInstance(rName string) string {
	return testAccAWSLBTargetGroupAttachmentConfigInstanceBase() + fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name     = %[1]q
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.test.id
}

resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.test.id
}
`, rName)
}

func testAccAWSLBTargetGroupAttachmentConfigPort(rName string) string {
	return testAccAWSLBTargetGroupAttachmentConfigInstanceBase() + fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name     = %[1]q
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.test.id
}

resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.test.id
  port             = 80
}
`, rName)
}

func testAccAWSLBTargetGroupAttachmentConfigBackwardsCompatibility(rName string) string {
	return testAccAWSLBTargetGroupAttachmentConfigInstanceBase() + fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name     = %[1]q
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.test.id
}

resource "aws_alb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.test.id
  port             = 80
}
`, rName)
}

func testAccAWSLBTargetGroupAttachmentConfigTargetIdIpAddress(rName string) string {
	return testAccAWSLBTargetGroupAttachmentConfigInstanceBase() + fmt.Sprintf(`
resource "aws_lb_target_group" "test" {
  name        = %[1]q
  port        = 443
  protocol    = "HTTPS"
  target_type = "ip"
  vpc_id      = aws_vpc.test.id
}

resource "aws_lb_target_group_attachment" "test" {
  availability_zone = aws_instance.test.availability_zone
  target_group_arn  = aws_lb_target_group.test.arn
  target_id         = aws_instance.test.private_ip
}
`, rName)
}

func testAccAWSLBTargetGroupAttachmentConfigTargetIdLambda(rName string) string {
	return fmt.Sprintf(`
data "aws_partition" "current" {}

resource "aws_lambda_permission" "test" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.test.arn
  principal     = "elasticloadbalancing.${data.aws_partition.current.dns_suffix}"
  qualifier     = aws_lambda_alias.test.name
  source_arn    = aws_lb_target_group.test.arn
  statement_id  = "AllowExecutionFromlb"
}

resource "aws_lb_target_group" "test" {
  name        = %[1]q
  target_type = "lambda"
}

resource "aws_lambda_function" "test" {
  filename      = "test-fixtures/lambda_elb.zip"
  function_name = %[1]q
  role          = aws_iam_role.test.arn
  handler       = "lambda_elb.lambda_handler"
  runtime       = "python3.7"
}

resource "aws_lambda_alias" "test" {
  name             = "test"
  description      = "a sample description"
  function_name    = aws_lambda_function.test.function_name
  function_version = "$LATEST"
}

resource "aws_iam_role" "test" {
  assume_role_policy = <<EOF
{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": "sts:AssumeRole",
				"Principal": {
					"Service": "lambda.${data.aws_partition.current.dns_suffix}"
				},
				"Effect": "Allow",
				"Sid": ""
			}
		]
	}
	EOF
}

resource "aws_lb_target_group_attachment" "test" {
  depends_on = [aws_lambda_permission.test]

  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_lambda_alias.test.arn
}
`, rName)
}
