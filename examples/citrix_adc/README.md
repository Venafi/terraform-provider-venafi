# Configuring secure application delivery using Citrix ADC and the _Venafi Provider for HashiCorp Terraform_

In this example, we'll show you how to better secure application delivery using _Venafi Provider for HashiCorp Terraform_ with your Citrix ADC instance. Adding Venafi enables you to manage certificates more securely as part of the TLS termination process on your load balancer.

## Who should use this example? 

The steps described in this example are typically performed by **DevOps engineers** or **system administrators**. Generally, you'll need a basic understanding of Citrix ADC, Venafi Trust Protection Platform or Venafi Cloud, and the required permissions for completing the tasks described in the example.

> **TIP** Having at least some basic knowledge of the Bash command language is helpful, such as when you need to set your provider locally.

## About this example 

In this example, we use Terraform's _infrastructure as code_ automation process with the _Venafi Provider_  to generate and install certificates as part of SSL termination on an ADC (specifically, Citrix ADC) for load balancing web traffic. We'll also utilize three HTTP servers contained in a cluster as the endpoints that are sending and receiving web traffic and being managed by Citrix ADC.

Later in this example, you'll generate a certificate for ``demo-citrix.venafi.example`` using the _Venafi Provider for Hashicorp Terraform_ with either Venafi Trust Protection Platform (TPP) or Venafi Cloud. Then after adding them to your Citrix ADC resources, you'll use them in the ADC node. And finally, you'll configure the service group members and [bind them](https://docs.citrix.com/en-us/citrix-adc/current-release/load-balancing/load-balancing-manage-large-scale-deployment/configure-service-groups.html#bind-a-service-group-to-a-virtual-server) to your ADC node.

> **NOTE** While we'll be using a ``Round robin`` balancing method in our ADC configuration, keep in mind that there are other [methods](https://docs.citrix.com/en-us/citrix-adc/current-release/load-balancing/load-balancing-customizing/assign-weight-services.html) that might be more suitable for your specific use case.

![scenario](scenario.png "Scenario")

### About retrieving a certificate using the _Venafi Provider for Terraform_

> **Best Practice:** In general, be careful when using self-signed certificates because of the inherent risks of no identity verification or trust control. The public and private keys are both held by the same entity. Also, self-signed certificates cannot be revoked; they can only be replaced. If an attacker has already gained access to a system, the attacker can spoof the identity of the subject. Of course, CAs can revoke a certificate only when they discover the compromise.

We'll be managing the following file structure:

```
./<your_workspace>/citrix_adc/
├── citrixadc-prereq.sh
├── citrix.tf
├── main.tf
├── venafi.tf
└── terraform.tfvars
```

We provided the needed files in this folder except for **terraform.tfvars**. The configuration of the file is customized by each user, which is why we provided **terraform.tfvars.example** for each Venafi platform that you could use for your own configuration.

## Prerequisites

Before you continue, carefully review these prerequisites:

- Verify that Terraform is installed correctly. [Look here for installation details.](https://learn.hashicorp.com/tutorials/terraform/install-cli).
- Verify that you have administrator access to your Citrix ADC instance.
- Install Citrix Terraform SDK locally; for instructions, [look here](./../base/README.md).
- Verify that you have administrator access to either Venafi Trust Protection Platform or Venafi Cloud Services.       - If you're using Trust Protection Platform and you do NOT have administrator access, you'll need to generate an access token from the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md), as described in [Trust between Terraform and Trust Protection Platform](https://github.com/Venafi/terraform-provider-venafi#trust-between-terraform-and-trust-protection-platform)) in the _Venafi Provider for HashiCorp Terraform_ README.
- Verify that you have three (3) web servers that are running your application; for this example, we'll use NGINX servers.

## Getting started 

Here are the steps we'll complete as we go through this example: 

1. Create your Terraform variables file.
2. Set up your main Terraform config file.
3. Set up your Venafi Terraform config file.
4. Set up your Citrix Terraform config file.
5. Apply your setup.
6. Test your implementation

>**NOTE** These steps reflect an example Terraform file structure and apply only to this example. Of course, you might be able to use a similar configuration, depending on your needs and preferences.

### Step 1: Create your Terraform variables file

The **terraform.tfvars** configuration for Citrix is divided by:

- Platform configuration (Venafi Cloud or TPP).
- Your Citrix management access.
- The configuration for your site.
- The Citrix Appliance where your data is stored.
- The Virtual IP and Port which is the entry point for your traffic-management object of your virtual server.
- The service group members are physical nodes on the network (NGINX servers for this example).

First we have to set the following variables depending on your platform that you are working on:

> **_Note:_** You can check how to set these variables and the `venafi_zone` in [here](https://github.com/Venafi/terraform-provider-venafi#usage).

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

And finally configure your Citrix infrastructure (these values are illustrative, you should change them accordingly to your own configutation):

```JSON
venafi_zone = "<venafi_zone>"

citrix_address = "192.168.x.x"
citrix_username = "your_citrix_user"
citrix_password = "your_password"

test_site_name = "demo-citrix"
test_site_domain = "venafi.example"

citrix_virtual_ip = "192.168.7.68"
citrix_virtual_port = "443"
citrix_service_group_members = [ "192.168.6.201:8001", "192.168.6.201:8002", "192.168.6.201:8003" ]
```

### Step 2: Set up your main Terraform config file

> **_Important:_** Make sure your local provider is [installed properly](./base/README.md).

1. Declare that the Venafi and Citrix ADC providers are required:
    ```
    terraform {
        required_providers {
            venafi = {
                source = "venafi/venafi"
                version = "~> 0.11.2"
            }
            citrixadc = {
                source = "path/to/citrix/citrixadc"
                version = "~> 0.12.0"
            }
        }
        required_version = ">= 0.13"
    }
    ```

2. Define you variables from **terraforms.vars**:

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

    variable "citrix_address" {
        type = string
    }

    variable "citrix_username" {
        type = string
    }

    variable "citrix_password" {
        type = string
    sensitive = true
    }

    variable "citrix_virtual_ip"{
        type = string
    }

    variable "citrix_virtual_port"{
        type = string
    }

    variable "citrix_service_group_members"{
        type = list(string)
    }
    ```
### Step 3: Set up your Venafi Terraform config file

1. Specify the connection and authentication settings for your Venafi provider this example:

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
        common_name = "${var.test_site_name}.${var.test_site_domain}"
        san_dns = [
            "${var.test_site_name}.${var.test_site_domain}"
        ]
        algorithm = "RSA"
        rsa_bits = 2048
        expiration_window = 720
    }
    ```

### Step 4: Set up your Citrix ADC Terraform config file

1. Set your Citrix ADC provider config:

    ```
    provider "citrixadc" {
        endpoint = "https://${var.citrix_address}/"
        username = var.citrix_username
        password = var.citrix_password
        insecure_skip_verify = true
    }
    ```

2. Set your Citrix ADC resources as it gets the content from the _venafi_certificate_ resource:
    ```
    resource "citrixadc_systemfile" "my_certfile" {
        filename = "${venafi_certificate.tls_server.common_name}.cert"
        filelocation = "/nsconfig/ssl"
        filecontent = venafi_certificate.tls_server.certificate
    }

    resource "citrixadc_systemfile" "my_keyfile" {
        filename = "${venafi_certificate.tls_server.common_name}.key"
        filelocation = "/nsconfig/ssl"
        filecontent = venafi_certificate.tls_server.private_key_pem
    }

    resource "citrixadc_systemfile" "my_chainfile" {
        filename = "${var.test_site_name}_chain.cert"
        filelocation = "/nsconfig/ssl"
        filecontent = venafi_certificate.tls_server.chain
    }

    resource "citrixadc_sslcertkey" "my_chain" {
        certkey = "${var.test_site_name}_ca_chain"
        cert = "${citrixadc_systemfile.my_certfile.filelocation}/${citrixadc_systemfile.my_chainfile.filename}"
        bundle = "NO"
        expirymonitor = "DISABLED"
    }
    ```

3. Create a resource to manages client SSL profiles on a Citrix to the ADC:

    ```
    resource "citrixadc_sslcertkey" "my_certkey" {
        certkey = "${var.test_site_name}.${var.test_site_domain}"
        cert = "${citrixadc_systemfile.my_certfile.filelocation}/${citrixadc_systemfile.my_certfile.filename}"
        key = "${citrixadc_systemfile.my_keyfile.filelocation}/${citrixadc_systemfile.my_keyfile.filename}"
        expirymonitor = "DISABLED"
        linkcertkeyname = citrixadc_sslcertkey.my_chain.certkey
    }
    ```

4. Create your service group members resources to manage membership in pools:

    ```
    resource "citrixadc_servicegroup" "my_pool" {
        servicegroupname = "${var.test_site_name}_pool"
        servicetype = "HTTP"
        lbvservers = [citrixadc_lbvserver.my_virtual_server.name]
        servicegroupmembers = var.citrix_service_group_members
    }
    ```

5. Create you resource in order to create your virtual server to manage your Citrix ADC:

    ```
    resource "citrixadc_lbvserver" "my_virtual_server" {
        name = "vs_${var.test_site_name}"
        ipv46 = var.citrix_virtual_ip
        port = var.citrix_virtual_port
        servicetype = "SSL"
        lbmethod = "ROUNDROBIN"
        sslcertkey = citrixadc_sslcertkey.my_certkey.certkey
        ciphersuites = ["DEFAULT"]
    }
    ```

6. For verification purposes, output the certificate, private key, and chain in PEM format and as a PKCS#12 keystore (base64-encoded):
    ```
    output "my_private_key" {
        value = venafi_certificate.tls_server.private_key_pem
        sensitive = true
    }

    output "my_certificate" {
        value = venafi_certificate.tls_server.certificate
    }

    output "my_trust_chain" {
        value = venafi_certificate.tls_server.chain
    }

    output "my_p12_keystore" {
        value = venafi_certificate.tls_server.pkcs12
    }
    ```

### Step 5: Apply your setup

Finally execute `terraform init`, ``terraform plan`` and ``terraform apply`` to apply your configuration changes. Then you should be able to log in your Citrix ADC appliance in `192.168.x.x` using ``<your_citrix_user>:<your_password>``.

If done correctly, you should see an output similar to the following:

[![asciicast](https://asciinema.org/a/xe0UUgiLKsaOhOXRqLu2bku9c.svg)](https://asciinema.org/a/xe0UUgiLKsaOhOXRqLu2bku9c)

To tear down your infrastructure, execute `terraform destroy`, and then you should see an output similar to this:

[![asciicast](https://asciinema.org/a/PrCtLI7cwkZC6RUriqpwuiQVU.svg)](https://asciinema.org/a/PrCtLI7cwkZC6RUriqpwuiQVU)

## What's next

After you've successfully implemented this example, consider the following tips:

<details>
    <summary><b>
        What happens when certificates expire? How do they get renewed? (click here to expand):
    </b></summary>

- _Whenever your certificate gets expired there are high chances you'll get an outage of users for using you application. Web browsers are programmed to rise a danger warning when this happens. Also there's a chance, depending of your ADC provider, it will turn off the appliances when one of certificates of the appliances it points to expires ([an example of an provider for previous mentioned sceneario](https://www.ibm.com/support/pages/one-expired-certificate-brings-down-all-certificates-datapower-validation-credential))._
- In order to renew a certificate you'll need to generate new [CSR](https://www.globalsign.com/en/blog/what-is-a-certificate-signing-request-csr). Once the certificate is ready, the CA will deliver it to you in order to install it to your appliance.
</details>

<details>
    <summary><b>
        How do certificates get validated? (click here to expand)
    </b></summary>
    
_The web server of you application send a copy of the SSL certificate to browser, which then makes a validation among the list of certificate authorities that are publicy trusted. Then the browser answers back a message whenever if the certificate was indeed signed by a trusted CA. Finally the web server start a SSL encrypted session with the web browser. You can check more about this [here](https://www.ssl.com/article/browsers-and-certificate-validation/)._
</details>
