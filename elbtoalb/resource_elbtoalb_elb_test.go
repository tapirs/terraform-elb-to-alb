package elbtoalb

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func init() {

}

// Unit test for listeners hash
func TestresourceElbtoalbElbListenerHash(t *testing.T) {
	cases := map[string]struct {
		Left  map[string]interface{}
		Right map[string]interface{}
		Match bool
	}{
		"protocols are case insensitive": {
			map[string]interface{}{
				"instance_port":     80,
				"instance_protocol": "TCP",
				"lb_port":           80,
				"lb_protocol":       "TCP",
			},
			map[string]interface{}{
				"instance_port":     80,
				"instance_protocol": "Tcp",
				"lb_port":           80,
				"lb_protocol":       "tcP",
			},
			true,
		},
	}

	for tn, tc := range cases {
		leftHash := resourceElbtoalbElbListenerHash(tc.Left)
		rightHash := resourceElbtoalbElbListenerHash(tc.Right)
		if leftHash == rightHash != tc.Match {
			t.Fatalf("%s: expected match: %t, but did not get it", tn, tc.Match)
		}
	}
}

func TestresourceElbtoalbELB_validateElbNameCannotBeginWithHyphen(t *testing.T) {
	var elbName = "-Testing123"
	_, errors := validateElbName(elbName, "SampleKey")

	if len(errors) != 1 {
		t.Fatalf("Expected the ELB Name to trigger a validation error")
	}
}

func TestresourceElbtoalbELB_validateElbNameCanBeAnEmptyString(t *testing.T) {
	var elbName = ""
	_, errors := validateElbName(elbName, "SampleKey")

	if len(errors) != 0 {
		t.Fatalf("Expected the ELB Name to pass validation")
	}
}

func TestresourceElbtoalbELB_validateElbNameCannotBeLongerThan32Characters(t *testing.T) {
	var elbName = "Testing123dddddddddddddddddddvvvv"
	_, errors := validateElbName(elbName, "SampleKey")

	if len(errors) != 1 {
		t.Fatalf("Expected the ELB Name to trigger a validation error")
	}
}

func TestresourceElbtoalbELB_validateElbNameCannotHaveSpecialCharacters(t *testing.T) {
	var elbName = "Testing123%%"
	_, errors := validateElbName(elbName, "SampleKey")

	if len(errors) != 1 {
		t.Fatalf("Expected the ELB Name to trigger a validation error")
	}
}

func TestresourceElbtoalbELB_validateElbNameCannotEndWithHyphen(t *testing.T) {
	var elbName = "Testing123-"
	_, errors := validateElbName(elbName, "SampleKey")

	if len(errors) != 1 {
		t.Fatalf("Expected the ELB Name to trigger a validation error")
	}
}

func TestresourceElbtoalbELB_validateAccessLogsInterval(t *testing.T) {
	type testCases struct {
		Value    int
		ErrCount int
	}

	invalidCases := []testCases{
		{
			Value:    0,
			ErrCount: 1,
		},
		{
			Value:    10,
			ErrCount: 1,
		},
		{
			Value:    -1,
			ErrCount: 1,
		},
	}

	for _, tc := range invalidCases {
		_, errors := validateAccessLogsInterval(tc.Value, "interval")
		if len(errors) != tc.ErrCount {
			t.Fatalf("Expected %q to trigger a validation error.", tc.Value)
		}
	}

}

func TestresourceElbtoalbELB_validateHealthCheckTarget(t *testing.T) {
	type testCase struct {
		Value    string
		ErrCount int
	}

	randomRunes := func(n int) string {
		rand.Seed(time.Now().UTC().UnixNano())

		// A complete set of modern Katakana characters.
		runes := []rune("アイウエオ" +
			"カキクケコガギグゲゴサシスセソザジズゼゾ" +
			"タチツテトダヂヅデドナニヌネノハヒフヘホ" +
			"バビブベボパピプペポマミムメモヤユヨラリ" +
			"ルレロワヰヱヲン")

		s := make([]rune, n)
		for i := range s {
			s[i] = runes[rand.Intn(len(runes))]
		}
		return string(s)
	}

	validCases := []testCase{
		{
			Value:    "TCP:1234",
			ErrCount: 0,
		},
		{
			Value:    "http:80/test",
			ErrCount: 0,
		},
		{
			Value:    fmt.Sprintf("HTTP:8080/%s", randomRunes(5)),
			ErrCount: 0,
		},
		{
			Value:    "SSL:8080",
			ErrCount: 0,
		},
	}

	for _, tc := range validCases {
		_, errors := validateHeathCheckTarget(tc.Value, "target")
		if len(errors) != tc.ErrCount {
			t.Fatalf("Expected %q not to trigger a validation error.", tc.Value)
		}
	}

	invalidCases := []testCase{
		{
			Value:    "",
			ErrCount: 1,
		},
		{
			Value:    "TCP:",
			ErrCount: 1,
		},
		{
			Value:    "TCP:1234/",
			ErrCount: 1,
		},
		{
			Value:    "SSL:8080/",
			ErrCount: 1,
		},
		{
			Value:    "HTTP:8080",
			ErrCount: 1,
		},
		{
			Value:    "incorrect-value",
			ErrCount: 1,
		},
		{
			Value:    "TCP:123456",
			ErrCount: 1,
		},
		{
			Value:    "incorrect:80/",
			ErrCount: 1,
		},
		{
			Value: fmt.Sprintf("HTTP:8080/%s%s",
				acctest.RandStringFromCharSet(512, acctest.CharSetAlpha), randomRunes(512)),
			ErrCount: 1,
		},
	}

	for _, tc := range invalidCases {
		_, errors := validateHeathCheckTarget(tc.Value, "target")
		if len(errors) != tc.ErrCount {
			t.Fatalf("Expected %q to trigger a validation error.", tc.Value)
		}
	}
}

func testAccCheckAWSELBAttributes(conf *elb.LoadBalancerDescription) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		l := elb.Listener{
			InstancePort:     aws.Int64(int64(8000)),
			InstanceProtocol: aws.String("HTTP"),
			LoadBalancerPort: aws.Int64(int64(80)),
			Protocol:         aws.String("HTTP"),
		}

		if !reflect.DeepEqual(conf.ListenerDescriptions[0].Listener, &l) {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				conf.ListenerDescriptions[0].Listener,
				l)
		}

		if *conf.DNSName == "" {
			return fmt.Errorf("empty dns_name")
		}

		return nil
	}
}

func testAccCheckAWSELBAttributesHealthCheck(conf *elb.LoadBalancerDescription) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		check := &elb.HealthCheck{
			Timeout:            aws.Int64(int64(30)),
			UnhealthyThreshold: aws.Int64(int64(5)),
			HealthyThreshold:   aws.Int64(int64(5)),
			Interval:           aws.Int64(int64(60)),
			Target:             aws.String("HTTP:8000/"),
		}

		if !reflect.DeepEqual(conf.HealthCheck, check) {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				conf.HealthCheck,
				check)
		}

		if *conf.DNSName == "" {
			return fmt.Errorf("empty dns_name")
		}

		return nil
	}
}

const testAccAWSELBConfig = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  cross_zone_load_balancing = true
}
`

func testAccAWSELBConfigTags1(tagKey1, tagValue1 string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  tags = {
    %[1]q = %[2]q
  }

  cross_zone_load_balancing = true
}
`, tagKey1, tagValue1)
}

func testAccAWSELBConfigTags2(tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  tags = {
    %[1]q = %[2]q
    %[3]q = %[4]q
  }

  cross_zone_load_balancing = true
}
`, tagKey1, tagValue1, tagKey2, tagValue2)
}

const testAccAWSELBFullRangeOfCharacters = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  name = "%s"
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

const testAccAWSELBAccessLogs = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

func testAccAWSELBAccessLogsOn(r string) string {
	return `
resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  access_logs {
    interval = 5
    bucket   = "${aws_s3_bucket.accesslogs_bucket.bucket}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}
` + testAccAWSELBAccessLogsCommon(r)
}

func testAccAWSELBAccessLogsDisabled(r string) string {
	return `
resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  access_logs {
    interval = 5
    bucket   = "${aws_s3_bucket.accesslogs_bucket.bucket}"
    enabled  = false
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}
` + testAccAWSELBAccessLogsCommon(r)
}

func testAccAWSELBAccessLogsCommon(r string) string {
	return fmt.Sprintf(`
data "aws_elb_service_account" "current" {}

data "aws_partition" "current" {}

resource "aws_s3_bucket" "accesslogs_bucket" {
  bucket        = "%[1]s"
  acl           = "private"
  force_destroy = true

  policy = <<EOF
{
  "Id": "Policy1446577137248",
  "Statement": [
    {
      "Action": "s3:PutObject",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${data.aws_elb_service_account.current.arn}"
      },
      "Resource": "arn:${data.aws_partition.current.partition}:s3:::%[1]s/*",
      "Sid": "Stmt1446575236270"
    }
  ],
  "Version": "2012-10-17"
}
EOF
}
`, r)
}

const testAccAWSELB_namePrefix = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  name_prefix = "test-"
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

const testAccAWSELBGeneratedName = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

const testAccAWSELB_zeroValueName = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  name               = ""
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}

# See https://github.com/terraform-providers/terraform-provider-aws/issues/2498
output "lb_name" {
  value = "${aws_elb.test.name}"
}
`

const testAccAWSELBConfig_AvailabilityZonesUpdate = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

const testAccAWSELBConfigNewInstance = `
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

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  instances = ["${aws_instance.test.id}"]
}

resource "aws_instance" "test" {
  ami           = "${data.aws_ami.amzn-ami-minimal-hvm-ebs.id}"
  instance_type = "t3.micro"
}
`

const testAccAWSELBConfigHealthCheck = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  health_check {
    healthy_threshold = 5
    unhealthy_threshold = 5
    target = "HTTP:8000/"
    interval = 60
    timeout = 30
  }
}
`

const testAccAWSELBConfigHealthCheck_update = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  health_check {
    healthy_threshold = 10
    unhealthy_threshold = 5
    target = "HTTP:8000/"
    interval = 60
    timeout = 30
  }
}
`

const testAccAWSELBConfigListener_update = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8080
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }
}
`

const testAccAWSELBConfigListener_multipleListeners = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  listener {
    instance_port = 22
    instance_protocol = "tcp"
    lb_port = 22
    lb_protocol = "tcp"
  }
}
`

const testAccAWSELBConfigIdleTimeout = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
	availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

	listener {
		instance_port = 8000
		instance_protocol = "http"
		lb_port = 80
		lb_protocol = "http"
	}

	idle_timeout = 200
}
`

const testAccAWSELBConfigIdleTimeout_update = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
	availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

	listener {
		instance_port = 8000
		instance_protocol = "http"
		lb_port = 80
		lb_protocol = "http"
	}

	idle_timeout = 400
}
`

const testAccAWSELBConfigConnectionDraining = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
	availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

	listener {
		instance_port = 8000
		instance_protocol = "http"
		lb_port = 80
		lb_protocol = "http"
	}

	connection_draining = true
	connection_draining_timeout = 400
}
`

const testAccAWSELBConfigConnectionDraining_update_timeout = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
	availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

	listener {
		instance_port = 8000
		instance_protocol = "http"
		lb_port = 80
		lb_protocol = "http"
	}

	connection_draining = true
	connection_draining_timeout = 600
}
`

const testAccAWSELBConfigConnectionDraining_update_disable = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
	availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

	listener {
		instance_port = 8000
		instance_protocol = "http"
		lb_port = 80
		lb_protocol = "http"
	}

	connection_draining = false
}
`

const testAccAWSELBConfigSecurityGroups = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]

  listener {
    instance_port = 8000
    instance_protocol = "http"
    lb_port = 80
    lb_protocol = "http"
  }

  security_groups = ["${aws_security_group.test.id}"]
}

resource "aws_security_group" "test" {
  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

	tags = {
		Name = "tf_elb_sg_test"
	}
}
`

func testAccELBConfig_Listener_IAMServerCertificate(certName, certificate, key, lbProtocol string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

resource "aws_iam_server_certificate" "test_cert" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

  listener {
    instance_port      = 443
    instance_protocol  = "%[4]s"
    lb_port            = 443
    lb_protocol        = "%[4]s"
    ssl_certificate_id = "${aws_iam_server_certificate.test_cert.arn}"
  }
}
`, certName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key), lbProtocol)
}

func testAccELBConfig_Listener_IAMServerCertificate_AddInvalidListener(certName, certificate, key string) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {}

resource "aws_iam_server_certificate" "test_cert" {
  name             = "%[1]s"
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_elb" "test" {
  availability_zones = ["${data.aws_availability_zones.available.names[0]}"]

  listener {
    instance_port      = 443
    instance_protocol  = "https"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "${aws_iam_server_certificate.test_cert.arn}"
  }

  # lb_protocol tcp and ssl_certificate_id is not valid
  listener {
    instance_port      = 8443
    instance_protocol  = "tcp"
    lb_port            = 8443
    lb_protocol        = "tcp"
    ssl_certificate_id = "${aws_iam_server_certificate.test_cert.arn}"
  }
}
`, certName, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

const testAccAWSELBConfig_subnets = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "azelb" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "terraform-testacc-elb-subnets"
  }
}

resource "aws_subnet" "public_a_one" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.1.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = {
    Name = "tf-acc-elb-subnets-a-one"
  }
}

resource "aws_subnet" "public_b_one" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.7.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[1]}"
  tags = {
    Name = "tf-acc-elb-subnets-b-one"
  }
}

resource "aws_subnet" "public_a_two" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.2.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = {
    Name = "tf-acc-elb-subnets-a-two"
  }
}

resource "aws_elb" "test" {
  name = "terraform-asg-deployment-example"

  subnets = [
    "${aws_subnet.public_a_one.id}",
    "${aws_subnet.public_b_one.id}",
  ]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  depends_on = ["aws_internet_gateway.gw"]
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.azelb.id}"

  tags = {
    Name = "main"
  }
}
`

const testAccAWSELBConfig_subnet_swap = `
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "azelb" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "terraform-testacc-elb-subnet-swap"
  }
}

resource "aws_subnet" "public_a_one" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.1.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = {
    Name = "tf-acc-elb-subnet-swap-a-one"
  }
}

resource "aws_subnet" "public_b_one" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.7.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[1]}"
  tags = {
    Name = "tf-acc-elb-subnet-swap-b-one"
  }
}

resource "aws_subnet" "public_a_two" {
  vpc_id = "${aws_vpc.azelb.id}"

  cidr_block        = "10.1.2.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = {
    Name = "tf-acc-elb-subnet-swap-a-two"
  }
}

resource "aws_elb" "test" {
  name = "terraform-asg-deployment-example"

  subnets = [
    "${aws_subnet.public_a_two.id}",
    "${aws_subnet.public_b_one.id}",
  ]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  depends_on = ["aws_internet_gateway.gw"]
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.azelb.id}"

  tags = {
    Name = "main"
  }
}
`
