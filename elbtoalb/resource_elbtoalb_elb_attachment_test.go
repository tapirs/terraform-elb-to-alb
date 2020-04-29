package elbtoalb

import (

)

// add one attachment
const testAccAWSELBAttachmentConfig1 = `
resource "aws_elb" "bar" {
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}

resource "aws_instance" "foo1" {
  # us-west-2
  ami           = "ami-043a5034"
  instance_type = "t1.micro"
}

resource "aws_elb_attachment" "foo1" {
  elb      = "${aws_elb.bar.id}"
  instance = "${aws_instance.foo1.id}"
}
`

// add a second attachment
const testAccAWSELBAttachmentConfig2 = `
resource "aws_elb" "bar" {
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}

resource "aws_instance" "foo1" {
  # us-west-2
  ami           = "ami-043a5034"
  instance_type = "t1.micro"
}

resource "aws_instance" "foo2" {
  # us-west-2
  ami           = "ami-043a5034"
  instance_type = "t1.micro"
}

resource "aws_elb_attachment" "foo1" {
  elb      = "${aws_elb.bar.id}"
  instance = "${aws_instance.foo1.id}"
}

resource "aws_elb_attachment" "foo2" {
  elb      = "${aws_elb.bar.id}"
  instance = "${aws_instance.foo2.id}"
}
`

// swap attachments between resources
const testAccAWSELBAttachmentConfig3 = `
resource "aws_elb" "bar" {
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}

resource "aws_instance" "foo1" {
  # us-west-2
  ami           = "ami-043a5034"
  instance_type = "t1.micro"
}

resource "aws_instance" "foo2" {
  # us-west-2
  ami           = "ami-043a5034"
  instance_type = "t1.micro"
}

resource "aws_elb_attachment" "foo1" {
  elb      = "${aws_elb.bar.id}"
  instance = "${aws_instance.foo2.id}"
}

resource "aws_elb_attachment" "foo2" {
  elb      = "${aws_elb.bar.id}"
  instance = "${aws_instance.foo1.id}"
}
`

// destroy attachments
const testAccAWSELBAttachmentConfig4 = `
resource "aws_elb" "bar" {
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}
`
