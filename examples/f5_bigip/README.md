# Configuring secure application delivery using F5 BIG-IP and the _Venafi Provider for HashiCorp Terraform_

In this example, we'll show you how to better secure application delivery using _Venafi Provider for HashiCorp Terraform_ with your F5 BIG-IP instance. Adding Venafi enables you to manage certificates more securely as part of the TLS termination process on your load balancer.
<!-- 
ORIGINAL TEXT: This example will guide you in mounting a [F5 BIG-IP](https://www.f5.com/products/big-ip-services) instance and make certificates for those sites using Venafi's product [HashiCorp Terraform](https://terraform.io/) implementation in order to provide [SSL termination](https://www.techwalla.com/articles/what-is-ssl-termination). 
-->
<!--
DW: Hi Ricardo, I think this first para should describe the desired outcome: state in simple terms what the user can expect when they implement your example. In fact, I re-wrote your title to state more directly what the desired outcome actually is (as I understand it): securing application delivery using Venafi Provider for HashiCorp Terraform with my F5 BIG-IP instance. My thinking is that while mounting an F5 BIG-IP instance is something the user will do to get to the outcome, it's not the end goal. And similarly, TLS termination is part of the process of securing app delivery using F5 and Venafi, but not the desired end goal. Does that make sense? 
-->
## Who should use this example?<!-- Suggest not using "Persona" as this is an UX term used more internally in software dev than a term that users would typically understand; while more techy people will use your example and might understand UX notion of personas, they are in this context a user. -->

The steps described in this example are typically performed by a **DevOps engineers** or **system administrators**. Generally, you'll need a basic understanding of F5 BIG-IP, Venafi Trust Protection Platform or Venafi Cloud, and the required permissions for completing the tasks described in the example.
<!--
DW: So I suggest adding--as I tried to do in that second sentence--the basic knowledge (as well as the permissions and access to the various systems) that is required in order to successfully complete your example. 
-->
## About this example <!--To make this more conversational and friendly, I've changed the title from "Scenario" to this one. -->

<!-- ORIGINAL TEXT: In order to increase reliability and capacity of applications, an application delivery controller(ADC) manages web traffic of your server application into nodes in order to reduce the "weight load" of those applications. --> <!-- DW: I took this first para out because I don't think we need to describe in this section what ADCs are and what they do. Remember, just my suggestion; if you think it's important, leave it here. -->

In this example, we use Terraform's _infrastructure as code_ automation process with the _Venafi Provider_ to generate and install certificates as part of SSL termination on a load balancer (F5 BIG-IP). We'll also utilize three HTTP servers contained in a cluster as the endpoints that are sending and receiving web traffic that's being managed by F5 BIG-IP.
<!-- 
**DW:** The original paragraph above wasn't clear to me; in my attempt to undersand it, I've written a new para. If I've lost the technical meaning, it's because I couldn't follow the original logic. Some of the questions I had from the original were these: Which parts of the explanation are Terraform's and which parts are Venafi...because the first half of the original sentence made it sound like Terraform has an automated process already for generating and installing certs, and so why woud you need Venafi? But I knew that's not true. So I wondered if it was saying that the Venafi Provider, as a service component of Terraform, is creating/installing the certs? In short, I wasn't clear which parts are us and which parts are Terraform, etc. And understanding that will I think help users stay oriented to "who's doing what" as they prepare to test drive your example. 
-->

<!-- I moved the following paragraphs below from what was called the Scenario Introduction section, which was below the Getting Started section, per our discussion on 31 March; we'd agreed that it makes more sense here and that it interupted the flow of the document in it's old location. -->
Later in this example, you'll generate a certificate for ``demo-f5-bigip.venafi.example`` using the _Venafi Provider for Hashicorp Terraform_ with either Venafi Trust Protection Platform (TPP) or Venafi Cloud. Then after adding them to your F5 BIG-IP resources, you'll use them in the ADC node. And finally, you'll configure the "pool" for your ADC nodes.

> **NOTE** While we'll be using a ``Round robin`` balancing method in our ADC configuration, keep in mind that there are [other methods](https://www.f5.com/services/resources/glossary/load-balancer) that might be more suitable for your specific use case.

![scenario](scenario.png "Scenario")

## About retrieving a certificate using the _Venafi Provider for Terraform_

> **NOTE** The only purpose of the credentials used in this example is illustrative, in a real life scenario they must be considered as **weak** and **insecure**. <!-- This seems like a strange place for this note; is this about the generic creds used in the steps below? And is the intent to tell users that they shouldn't use simple passwords (e.g. "password") in production environments? Once I understand the purpose, I can suggest some changes... -->

We'll be managing the following file structure:

```
./<your_workspace>/f5_bigip/
├── f5bigip.tf
├── main.tf
├── venafi.tf
└── terraform.tfvars
```

We provided the needed files in this folder, except for **terraform.tfvars**. The configuration of the file is customized by each user, which is why we provided **terraform.tfvars.example** for each Venafi Platform that you could use to set your own configuration.

## Prerequisites

Before you continue, carefully review these prerequisites first:

- Verify that Terraform is installed correctly. [Look here for installation details.](https://learn.hashicorp.com/tutorials/terraform/install-cli).
- Verify that you have administrator access to either Venafi Trust Protection Platform or Venafi Cloud Services        - If you're using Trust Protection Platform and you do NOT have administrator access, you'll need to generate an access token from the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md), as described in [Trust between Terraform and Trust Protection Platform](https://github.com/Venafi/terraform-provider-venafi#trust-between-terraform-and-trust-protection-platform)) in the _Venafi Provider for HashiCorp Terraform_ README.
- Verify that you have administrator access to your F5 BIG-IP instance
- Verify that you have three (3) web servers that are running your application; for this example, we'll use NGINX servers.

## Getting started <!-- To give your document more of a flow forward, I changed the title from "Solution" to this one. Users love this title because it's like a sign-post letting them know that now we're getting down to business! -->

Here are the steps we'll take as we go through this example:

1. Create your Terraform variables file
2. Set you main Terraform config file
3. Set your Venafi Terraform config file
4. Set your F5 BIG IP Terraform config file
5. Apply your setup

>**NOTE** These steps reflect an example Terraform file structure and apply to this example only. Of course, you might be able to use a similar configuration, depending on your needs and preferences.

### Step 1: Create your Terraform variables file

The **terraform.tfvars** configuration for F5 is divided by the following:

- Platform configuration (Venafi Cloud or TPP)
- Your F5 floating managment access
- The configuration for your site
- The F5 partition where your data is stored
- The Virtual IP and Port, which is the entry point for your traffic-management object of your virtual server
- The pool members are physical nodes on the network (NGINX servers, in this example)

First, we have to set the following variables depending on your platform that you are working on:

> **NOTE** [Learn how to set these variables and the `venafi_zone`](https://github.com/Venafi/terraform-provider-venafi#usage).

**TPP**:
```JSON
tpp_url = "https://tpp.example"
bundle_path = "<bundle_path>"
access_token = "<access_token>"
```

**Venafi Cloud**:
```JSON
venafi_api_key = "<venafi_api_key>"
```

And finally, configure your F5 infrastructure: 

>**NOTE** The values we use here are for illustration only; you should change them according to your own configutation.

```JSON
venafi_zone = "<venafi_zone>"

f5_address = "192.168.x.x"
f5_username = "your_f5_user"
f5_password = "your_password"

test_site_name = "demo-f5-bigip"
test_site_domain = "venafi.example"

f5_partition = "Demo"
f5_virtual_ip = "192.168.7.68"
f5_virtual_port = "443"
f5_pool_members = [ "192.168.6.201:8001", "192.168.6.201:8002", "192.168.6.201:8003" ]
```

### Step 2: Set up your main Terraform config file

1. Declare that the Venafi and F5 BIG-IP providers are required:
    ```
    terraform {
        required_providers {
            venafi = {
                source = "venafi/venafi"
                version = "~> 0.11.0"
            }
            bigip = {
                source = "f5networks/bigip"
                version = "~> 1.5.0"
            }
        }
        required_version = ">= 0.13"
    }
    ```

2. Define your variables from **terraforms.vars**:

    **TPP**:
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

    **Venafi Cloud**:
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

    variable "f5_address" {
        type = string
    }

    variable "f5_username" {
        type = string
    }

    variable "f5_password" {
        type = string
        sensitive = true
    }

    variable "f5_partition" {
        type = string
    }

    variable "f5_virtual_ip" {
        type = string
    }

    variable "f5_virtual_port" {
        type = string
    }

    variable "f5_pool_members" {
        type = list(string)
    }
    ```
### Step 3: Set up your Venafi Terraform config file

1. Specify the connection and authentication settings for your Venafi provider:

    **TPP**:
    ```
    provider "venafi" {
        url          = var.tpp_url
        trust_bundle = file(var.bundle_path)
        access_token = var.access_token
        zone         = var.venafi_zone
    }
    ```

    **Venafi Cloud**:
    ```
    provider "venafi" {
        api_key = var.venafi_api_key
        zone = var.venafi_zone
    }
    ```

2. Create a `venafi_certificate` **resource** that will generate a new key pair and enroll the certificate needed by a _"tls_server"_ application:
    ```
    resource "venafi_certificate" "tls_server" {
        common_name = "${var.test_site_name}-${formatdate("YYYYMMDD-hhmmss", timestamp())}.${var.test_site_domain}"
        san_dns = [
            "${var.test_site_name}.${var.test_site_domain}"
        ]
        algorithm = "RSA"
        rsa_bits = 2048
        expiration_window = 720
    }
    ```

### Step 4: Set up your F5 BIG IP Terraform config file

1. Set your F5 BIG-IP provider config:

    ```
    provider "bigip" {
        address  = var.f5_address
        username = var.f5_username
        password = var.f5_password
    }
    ```

2. Set your *asset_name* for your vars in `locals` (remember that locals<sup>[1](https://www.terraform.io/docs/language/values/locals.html)</sup> are values that can be used multiple times within a module without repeating it):

    ```
    locals {
        asset_name = "${var.test_site_name}.${var.test_site_domain}"
    }
    ```

3. Set your F5 BIG-IP resources as it gets the content from the _venafi_certificate_ resource:
    ```
    resource "bigip_ssl_key" "my_key" {
        name      = "${local.asset_name}.key"
        content   = venafi_certificate.tls_server.private_key_pem
        partition = var.f5_partition
    }

    resource "bigip_ssl_certificate" "my_cert" {
        name      = "${local.asset_name}.crt"
        content   = venafi_certificate.tls_server.certificate
        partition = var.f5_partition
    }

    resource "bigip_ssl_certificate" "my_chain" {
        name      = "${local.asset_name}-ca-bundle.crt"
        content   = venafi_certificate.tls_server.chain
        partition = var.f5_partition
    }
    ```

4. Create a resource to manages client SSL profiles on a BIG-IP from the F5 partition<sup>[2](https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_profile_client_ssl)</sup>:

    ```
    resource "bigip_ltm_profile_client_ssl" "my_profile" {
        name           = "/${var.f5_partition}/clientssl_${var.test_site_name}"
        defaults_from  = "/Common/clientssl"
        cert_key_chain {
            name  = bigip_ssl_certificate.my_cert.name
            cert  = "/${var.f5_partition}/${bigip_ssl_certificate.my_cert.name}"
            key   = "/${var.f5_partition}/${bigip_ssl_key.my_key.name}"
            chain = "/${var.f5_partition}/${bigip_ssl_certificate.my_chain.name}"
        }
    }
    ```

5. Create your pool members resources to manage membership in pools<sup>[3](https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_pool_attachment)</sup>:

    ```
    resource "bigip_ltm_pool" "my_pool" {
        name                   = "/${var.f5_partition}/pool_${var.test_site_name}"
        load_balancing_mode    = "round-robin"
        minimum_active_members = 1
        monitors               = ["/Common/http"]
    }

    resource "bigip_ltm_pool_attachment" "my_pool_node" {
        pool     = bigip_ltm_pool.my_pool.name
        for_each = toset(var.f5_pool_members)
        node     = each.key
    }
    ```

6. Create you resource in order to create your virtual server to manage your F5 partition<sup>[4](https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_virtual_server)</sup>:

    ```
    resource "bigip_ltm_virtual_server" "my_virtual_server" {
        name                       = "/${var.f5_partition}/vs_${var.test_site_name}"
        description                = "Provisioned by Terraform"
        destination                = var.f5_virtual_ip
        port                       = var.f5_virtual_port
        client_profiles            = [bigip_ltm_profile_client_ssl.my_profile.name]
        source_address_translation = "automap"
        pool                       = bigip_ltm_pool.my_pool.name
    }
    ```

### Step 5: Apply your setup

Finally, execute `terraform init`, ``terraform plan`` and ``terraform apply`` to apply your configuration changes. Then you should be able to log into your F5 partition in `192.168.x.x` using ``<your_f5_user>:<your_password>``.

If done correctly, you should see an output similar to the following:

[![asciicast](https://asciinema.org/a/fKmvGRMCGxSaLN6EodmedsRpg.svg)](https://asciinema.org/a/fKmvGRMCGxSaLN6EodmedsRpg)
To tear down your F5 partition execute `terraform destroy`, then you should see an output like this:

[![asciicast](https://asciinema.org/a/V7TthUjHaejww5miuUbAnmyQS.svg)](https://asciinema.org/a/V7TthUjHaejww5miuUbAnmyQS)

## What's next
<!-- should keep this section brief; if the answer is more than a small paragraph, I suggest that you link to another article/topic/website somewhere -->

After you've successfully implemented this example, consider the following tips:

- **What happens when certificates expire? How do they get renewed?** (BriefAnswerHere)

- **How do certificates get validated?** (BriefAnswerHere)

<!-- Depending on your MD language, you could format these as expandable text so users can click the bullet item to reveal your answers. -->

## Helpful references 
<!-- I think if you use this idea of providing links to third-party resources, that we should make it part of our template; otherwise, I would move these links one at a time up into your content where it makes the most sense and is in context -->

1. https://www.terraform.io/docs/language/values/locals.html
2. https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_profile_client_ssl
3. https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_pool_attachment
4. https://registry.terraform.io/providers/F5Networks/bigip/latest/docs/resources/bigip_ltm_virtual_server
