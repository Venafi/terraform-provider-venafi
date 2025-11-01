# Configuring secure application delivery using AWS ACM and the _Venafi Provider for Hashicorp Terraform_

In this example, we'll show you how to better secure application deliver using _Venafi Provider for Hashicorp Terraform_ with AWS ACM and ALBs. That will enable you to manage certificates more securely as part of the TLS termination process on your load balancer.

## About this example

In this example, we use Terraform's _intrastructure as code_ automation process with the _Venafi Provider_ to generate and install certificates within AWS ACM as part of SSL Termination on AWS ALB for load balancing web traffic. 

### About retrieving a certificate using the _Venafi Provider for Terraform_

> **BEST PRACTICES** In general, be careful when using self-signed certificates because of the inherent risks of no identity verification or trust control. The public and private keys are both held by the same entity. Also, self-signed certificates cannot be revoked; they can only be replaced. If an attacker has already gained access to a system, the attacker can spoof the identity of the subject. Of course, CAs can revoke a certificate only when they discover the compromise.

We'll be managing the following file structure:

```
./<your_workspace>/aws_elb/
├── aws-vpc.tf
├── aws-elb.tf
├── main.tf
├── venafi.tf
└── terraform.tfvars
```

We provided the needed files in this folder except for _terraform.tfvars_. The configuration of the file is customized by each user, which is why we provided _terraform.tfvars.example_ for each CyberArk platform that you could use for your own configuration.

## Prerequisites

Before you continue, carefully review these prerequisites:

- Verify that Terraform is installed correctly. [Look here for installation details.](https://learn.hashicorp.com/tutorials/terraform/install-cli).
- Verify you have permission and access to create specific AWS resources such as EC2 instances and Load Balancers.
- Verify that you have administrator access to either CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS.  
- If you're using CyberArk Certificate Manager, Self-Hosted and you do NOT have administrator access, you'll need to generate an access token from the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md), as described in [Trust between Terraform and CyberArk Certificate Manager, Self-Hosted](https://github.com/Venafi/terraform-provider-venafi#trust-between-terraform-and-trust-protection-platform)) in the _Venafi Provider for HashiCorp Terraform_ README.

## Getting started

Here are the steps we'll complete as we go through this example:

1. Create your Terraform variables file.
2. Set up your main Terraform config file.
3. Set up your CyberArk Terraform config file.
4. Setup your AWS Terraform config files.
5. Apply your setup.
6. Test your implementation.

>**NOTE** These steps reflect an example Terraform file structure and apply only to this example. Of course, you might be able to use a similar configuration, depending on your needs and preferences.

### Step 1: Create your Terraform variables file

The _terraform.tfvars_ configuration for AWS is divided into the following sections:

- Platform configuration (CyberArk Certificate Manager, SaaS or CyberArk Certificate Manager, Self-Hosted)
- The configuration for your site
- AWS VPC configuration

First we have to set the following variables depending on your platform that you are working on:

> **NOTE** You can check how to set these variables and the `venafi_zone` in [here](https://github.com/Venafi/terraform-provider-venafi#usage).

**CyberArk Certificate Manager, Self-Hosted**:
```JSON
tpp_url = "https://tpp.example"
bundle_path = "<bundle_path>"
access_token = "<access_token>"
```

**CyberArk Certificate Manager, SaaS**:
```JSON
venafi_api_key = "<venafi_api_key>"
```

And finally configure your AWS infrastructure: 

> **NOTE** The values we use here are for illustration only; you should change them according to your own configuration.

```JSON
venafi_zone = "<venafi_zone>"
test_site_name = "demo-aws" 
test_site_domain = "venafi.example" 
aws_vpc_cidr = "10.0.0.0/16"
aws_vpc_azs = [ "us-east-1a", "us-east-1c"]
aws_vpc_private_subnets = [ "10.0.12.0/24", "10.0.24.0.24" ]
aws_vpc_public_subnets = [ "10.0.36.0/24", "10.0.48.0/24" ]
```

### Step 2: Set up your main Terrafrom config file

1. Declare that the CyberArk and AWS providers are required:
    ```
    terraform {
        required_providers {
            venafi = {
                source = "venafi/venafi"
                version = "~> 0.20.0"
            }
            aws = {
                source = "hashicorp/aws"
                version = "~> 3.10.0"
            }
        }
        required_version = ">= 0.13"
    }
    ```

2. Define your variables from _terraform.tfvars_:

    **CyberArk Certificate Manager, Self-Hosted**:
    ```
    variable "tpp_url" {
        type = string
    }
    
    variable "bundle_path" {
        type = string
    }

    variable "access_token" {
        type = string
    }
    ```

    **CyberArk Certificate Manager, SaaS**:
    ```
    variable "venafi_api_key" {
        type = string
        sensitive = true
    }
    ```

    Then, define the following:
    ```
    variable "venafi_zone" {
        type = string
    }

    variable "test_site_name" {
        type = string
    }

    variable "test_site_domain" {
        type = string
    }

    variable "aws_vpc_cidr" {
        type = string
    }

    variable "aws_vpc_azs" {
        type = list(string)
    }

    variable "aws_vpc_private_subnets" {
        type = list(string)
    }

    variable "aws_vpc_public_subnets" { 
        type = list(string)
    }
    ```

### Step 3: Set up your CyberArk Terraform config file

1. Specify the connection and authentication settings for your Venafi Provider:

    **CyberArk Certificate Manager, Self-Hosted**:
    ```
    provider "venafi" {
        url          = var.tpp_url
        trust_bundle = file(var.bundle_path)
        access_token = var.access_token
        zone         = var.venafi_zone
    }
    ```

    **CyberArk Certificate Manager, SaaS**:
    ```
    provider "venafi" {
        api_key = var.venafi_api_key
        zone = var.venafi_zone
    }
    ```

2. Create a `venafi_certificate` _resource_ that will generate a new key pair and enroll the certificate needed by a _"tls_server"_ application:


    ```
    resource "venafi_certificate" "webserver" {
        common_name = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}.${var.test_site_domain}"
        algorithm   = "RSA"
        rsa_bits    = 2048
        san_dns = [
            "${var.test_site_name}.${var.test_site_domain}"
        ]
    }
    ```

### Step 4: Set up your AWS Terraform config files

1. Specify your AWS provider configuration:

    ```
    provider "aws" {
        region = "us-east-1"
    }
    ```

2. Specify AWS EC2 instance data:

    ```
    data "aws_ami" "linux" {
        most_recent = "true"
        owners      = ["amazon"]

        filter {
            name   = "name"
            values = ["amzn2-ami-hvm*"]
        }
    }
    ```

3. Set your AWS ACM resource as it gets content from the _venafi-certificate_ resource: 

    ```
    resource "aws_acm_certificate" "cert" {
        private_key       = venafi_certificate.webserver.private_key_pem
        certificate_body  = venafi_certificate.webserver.certificate
        certificate_chain = venafi_certificate.webserver.chain
    }
    ```

4. Create AWS resources security groups.

    ```
    resource "aws_security_group" "allow_tls" {
        name        = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}-allow_tls"
        description = "Allow TLS inbound traffic"
        vpc_id      = module.vpc.vpc_id

        ingress {
            from_port   = 443
            to_port     = 443
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
        }

        ingress {
            from_port   = 80
            to_port     = 80
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
        }

        egress {
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }

    resource "aws_security_group" "ec2-instance-http" {
        name        = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}-ec2-instance"
        description = "Allows inbound HTTP access"
        vpc_id      = module.vpc.vpc_id

        ingress {
            from_port       = 80
            to_port         = 80
            protocol        = "tcp"
            security_groups = [aws_security_group.allow_tls.id]
        }

        egress {
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }   
    ```

5. Create AWS LoadBalancer listeners.
    ```
    resource "aws_lb_listener" "external-listener" {
        load_balancer_arn = aws_lb.external-alb.arn
        port              = "443"
        protocol          = "HTTPS"
        ssl_policy        = "ELBSecurityPolicy-2016-08"
        certificate_arn   = aws_acm_certificate.cert.arn

        default_action {
            type             = "forward"
            target_group_arn = aws_lb_target_group.external-target.arn
        }
    }   

    resource "aws_lb_listener" "external-listener-http-redirect" {
        load_balancer_arn = aws_lb.external-alb.arn
        port              = "80"
        protocol          = "HTTP"

        default_action {
            type = "redirect"

            redirect {
                port        = "443"
                protocol    = "HTTPS"
                status_code = "HTTP_301"
            }
        } 
    }   
    ```

6. Create AWS EC2 instance and Load Balancer

    ```
    resource "aws_lb_target_group" "external-target" {
        name     = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}-lb-tg"
        port     = 80
        protocol = "HTTP"
        vpc_id   = module.vpc.vpc_id
    }

    resource "aws_lb" "external-alb" {
        name               = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}-ext-lb"
        internal           = false
        load_balancer_type = "application"
        security_groups    = [aws_security_group.allow_tls.id]
        subnets            = [module.vpc.public_subnets[0], module.vpc.public_subnets[1]]
    }

    resource "aws_lb_target_group_attachment" "ec2-tg-attachment" {
        target_group_arn = aws_lb_target_group.external-target.arn
        target_id        = aws_instance.apache-server.id
        port             = 80
    }

    resource "aws_instance" "apache-server" {
        ami                         = data.aws_ami.linux.id
        instance_type               = "t2.micro"
        vpc_security_group_ids      = [aws_security_group.ec2-instance-http.id]
        subnet_id                   = module.vpc.public_subnets[0]
        associate_public_ip_address = true
        tags = {
            Name = "Sample Apache Server"
        }
        user_data = <<EOF
                #! /bin/bash
                yum update -y
                yum -y install httpd
                service httpd start
                echo '<html><h1>Hello World!</h1></html>' > var/www/html/index.html
        EOF
    }
    ```

### Step 5: Apply your setup

Finally, run `terraform init`, ``terraform plan`` and ``terraform apply`` to apply your configuration changes.