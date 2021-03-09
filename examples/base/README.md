# Building your unregistered provider


First we have to take the current project url from github
and tear it down as follows:

```
https://github.com/owner/project_name/releases/download/v{{version}}/asset-name
```

Taking [citrix terraform module](https://github.com/citrix/terraform-provider-citrixadc) for example:

```LOG
https://github.com/citrix/terraform-provider-citrixadc/releases/download/v0.12.36/terraform-provider-citrixadc_0.12.36_linux_amd64.tar.gz
```

Build our .env file:

**.env**
```
CITRIX_PROVIDER_VERSION=0.12.36
OWNER=citrix
PROJECT_NAME=terraform-provider-citrixadc
ASSET_NAME=terraform-provider-citrixadc_0.12.36_linux_amd64.tar.gz
```

Add this script:

**citrixadc-prereq.sh**
```BASH
#!/bin/bash

if [ -f .env ]
then
  export $(cat .env | sed 's/#.*//g' | xargs)
fi

PROVIDERS_DIR=${PWD}/providers
PROVIDER_PATH=${PROVIDERS_DIR}/localhost/citrix/citrixadc/${CITRIX_PROVIDER_VERSION}/linux_amd64

CITRIX_URL=https://github.com/${OWNER}/${PROJECT_NAME}/releases/download/v${CITRIX_PROVIDER_VERSION}/${ASSET_NAME}

wget $CITRIX_URL

mkdir -p $PROVIDER_PATH

tar -xf $ASSET_NAME -C $PROVIDER_PATH

cat >.terraformrc <<EOF
provider_installation {
  filesystem_mirror {
    path    = "${PROVIDERS_DIR}"
    include = ["local/citrix/citrixadc"]
  }
  direct {
    exclude = ["local/*/*"]
  }
}
EOF

echo export TF_CLI_CONFIG_FILE=${PWD}/.terraformrc
```

Then execute:

```BASH
$ ./citrixadc-prereq.sh
```

## Known issues

```LOG
Error: Failed to query available provider packages

Could not retrieve the list of available versions for provider
localhost/citrix/citrixadc: could not connect to localhost: Failed to request
discovery document: Get "https://localhost/.well-known/terraform.json": dial
tcp 127.0.0.1:443: connect: connection refused
```

The error may be offleading, since Terraform is actually loading its default configuration (and looking for a [Provider Network Mirror Protocol](https://www.terraform.io/docs/internals/provider-network-mirror-protocol.html)) instead of the one provided [locally](https://www.terraform.io/docs/cli/config/config-file.html#explicit-installation-method-configuration) built by our bash script.

Make sure is set correctly by executing the following in your CLI:

```BASH
echo $TF_CLI_CONFIG_FILE
```

You should have an output like this:

```LOG
opensource@venafihost/path/to/your-workspace$ 
/path/to/your-workspace.terraformrc
```