# terraform-provider-venafi

## Pre-requisites
Go 1.7 or higher.

## Building

With govcert cloned in either `$GOPATH/src/github.com/Venafi/govcert` or `./vendor/github.com/Venafi/govcert`, from within the `terraform-provider-venafi` directory run:

```
go get -v ./...
go build
```

This will create the binary `terraform-provider-venafi`. To have terraform pick this up and use it copy the binary to a location on your `$PATH`.

## Usage
### Create provider
To use the terraform provider create a `venafi.tf` file. In here you must first create the provider. This would be done by creating a provider block.

```
provider "venafi" {
    api_key = "<API_KEY>"
    zone    = "<ZONE>"      //optional. Defaults to 'default'
}
```

### Creating a Certificate Signing Request

Certificate signing requests can be created using the `venafi_csr` resource. This resource only has 1 required field.
- `common_name` (string)

The following optional fields can also be set

| field                | type         |
| -------------------- | ------------ |
| `organizational_unit`| string array |
| `organization_name`  | string       |
| `country`            | string       |
| `state`              | string       |
| `locality`           | string       |
| `key_password`       | string       |
| `san_dns`            | string array |
| `san_email`          | string array |
| `san_ip`             | string array |

After creation this resource will expose 2 further fields

| field             |type    |
| ----------------- | ------ |
| `private_key_pem` | string |
| `csr_pem`         | string |

The following example would output the created private key and csr
```
provider "venafi" {
    ...
}

resource "venafi_csr" "webserver" {
    common_name = "web.vendev.com"
    san_dns = ["blog.vendev.com", "contact.vendev.com"]
    organizational_unit = ["appdev", "webdev"]
    state = "London"
    country = "UK"
}

output "csr" {
    value = "${venafi_csr.webserver.csr_pem}"
}

output "csr_private_key" {
    value = "${venafi_csr.webserver.private_key_pem}"
}
```

### Creating a Certificate / Private Key pair

Certificate signing requests can be created using the `venafi_certificate` resource. This resource only has 1 required field.
- `common_name` (string)

The following optional fields can also be set

| field          | type                                 |
| -------------- | ------------------------------------ |
| `algorithm`    | string [RSA or ECDSA]                |
| `rsa_bits`     | integer (Used when `algorithm`=RSA)  |
| `ecdsa_curve`  | string (Used when `algorithm`=ECDSA) |
| `san_dns`      | string array                         |
| `san_email`    | string array                         |
| `san_ip`       | string array                         |
| `key_password` | string                               |

After creation this resource will expose 3 further fields

| field             |type    |
| ----------------- | ------ |
| `private_key_pem` | string |
| `chain`           | string |
| `certificate`     | string |

The following example would output the created private key and csr

```
provider "venafi" {
    ...
}

resource "venafi_certificate" "webserver" {
    common_name = "web.vfidev.com"
    algorithm = "RSA"
    rsa_bits = "2048"
    san_dns = [
        "web01.vfidev.com",
        "web02.vfidev.com"
    ]
    key_password = "${var.pk_pass}"
}

output "cert_certificate" {
    value = "${venafi_certificate.webserver.certificate}"
}

output "cert_chain" {
    value = "${venafi_certificate.webserver.chain}"
}

output "cert_private_key" {
    value = "${venafi_certificate.webserver.private_key_pem}"
}
```
