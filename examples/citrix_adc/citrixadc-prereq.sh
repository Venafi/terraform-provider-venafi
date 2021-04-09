#!/bin/bash

if [ -f .env ]
then
  export $(cat .env | sed 's/#.*//g' | xargs)
fi

PROVIDERS_DIR=${PWD}/providers
PROVIDER_PATH=${PROVIDERS_DIR}/localhost/citrix/citrixadc/${PROJECT_VERSION}/linux_amd64

PROJECT_URL=https://github.com/${PROJECT_OWNER}/${PROJECT_NAME}/releases/download/v${PROJECT_VERSION}/${ASSET_NAME}

wget -qN $PROJECT_URL

mkdir -p $PROVIDER_PATH

tar -xf $ASSET_NAME -C $PROVIDER_PATH

cat >.terraformrc <<EOF
provider_installation {
  filesystem_mirror {
    path    = "${PROVIDERS_DIR}"
    include = ["localhost/citrix/citrixadc"]
  }
  direct {
    exclude = ["localhost/*/*"]
  }
}
EOF

export TF_CLI_CONFIG_FILE=${PWD}/.terraformrc
echo "export TF_CLI_CONFIG_FILE="$TF_CLI_CONFIG_FILE
