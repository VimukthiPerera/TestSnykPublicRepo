#!/usr/bin/env bash
# -------------------------------------------------------------------------------------
#
# Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
#
# This software is the property of WSO2 Inc. and its suppliers, if any.
# Dissemination of any information or reproduction of any material contained
# herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
# You may not alter or remove any copyright or other notice from copies of this content.
#
# --------------------------------------------------------------------------------------
set -e

# Prepare key stores for Identity Server deployment

echo "-----------------------------------------------------"
echo "| Security Deployment Sentinel rules and Logic Apps |"
echo "-----------------------------------------------------"

function print_usage {
    echo -e "Usage: $0 [options]\n";
    echo -e "Options:\n"
    echo "--project                    - Name of the Project [default: \"security\"]";
    echo "--env                        - Name of the Environment {non-prod, prod}. This value should exactly match the folder in env";
    echo "--rg                         - Name of the Azure Resource group to deploy the Resources and the ARM Spec";
    echo "--location                   - Azure Location to do the deployment";
    echo;
    echo "e.g. $0 --project=security --env=non-prod --rg=non-prod-rg --location=eastus2";
    exit 1;
}

# Global variables
SPEC_NAME="AS-RLA-SPEC"
readonly SPEC_NAME
SCRIPT_PATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
readonly SCRIPT_PATH
VERSION="4"
readonly VERSION
AZ="$(which az)"
readonly AZ
SUBSID="$($AZ account show --query id --output tsv)"
readonly SUBSID

for arg in "$@"
do
    case $arg in
        --env=*)
        ENV="${arg#*=}"
        shift
        ;;
        --rg=*)
        RG="${arg#*=}"
        shift
        ;;
        --location=*)
        LOCATION="${arg#*=}"
        shift
        ;;
        *)
        OTHER_ARGUMENTS+=("$1")
        shift
        ;;
    esac
done

if [[ (( -z "${LOCATION}" ) || ( -z "${RG}" )) || ( -z "${ENV}" )  ]]; then
    print_usage
fi

echo "Create the ARM linked template Spec"
$AZ ts create --name ${SPEC_NAME} --version ${VERSION} --resource-group "${RG}" --location "${LOCATION}" \
      --template-file "${SCRIPT_PATH}/azuredeploy.json" --verbose

echo "Create Infrastructure using the ARM Spec spec ID"
$AZ deployment group create --resource-group "${RG}" \
    --template-spec "/subscriptions/${SUBSID}/resourceGroups/${RG}/providers/Microsoft.Resources/templateSpecs/${SPEC_NAME}/versions/${VERSION}" \
    --parameters "@product-deployment/arm-templates/conf/${ENV}.setup.parameters.json" --verbose

###### Limitation
### Add any limitations here
