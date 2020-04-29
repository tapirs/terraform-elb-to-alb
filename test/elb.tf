provider "elbtoalb" {
}

resource "elbtoalb_elb" "ms_elb" {
  name     = "elb-ms"
  internal = true

  access_logs {
    bucket        = "dwp-cloudservices-searchlight-log"
    bucket_prefix = "elb-ms"
    interval      = 5
  }

  listener {
    instance_port     = 8080
    instance_protocol = "tcp"
    lb_port           = 8080
    lb_protocol       = "tcp"
  }

  listener {
    instance_port     = 4000
    instance_protocol = "tcp"
    lb_port           = 4000
    lb_protocol       = "tcp"
  }

  listener {
    instance_port     = 4090
    instance_protocol = "tcp"
    lb_port           = 4090
    lb_protocol       = "tcp"
  }

  listener {
    instance_port     = 8080
    instance_protocol = "tcp"
    lb_port           = 443
    lb_protocol       = "tcp"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "TCP:8080"
    interval            = 30
  }

  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

}
