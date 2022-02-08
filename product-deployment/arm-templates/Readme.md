# Azure Logic Apps for Sentinel

This creates Azure Logic Apps for Sentinel. Azure Resource Manager template Specs are used here. ARM template specs can be found [here](https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/template-specs-create-linked?tabs=azure-powershell).

## Instructions on Creating the Deployment

### Prerequisites

#### Tools

1. [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) (version = `2.15.1`)
2. Perform Azure login [properly setup](https://docs.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest#az-login) with `az login` will list all the available subscriptions. Configure the az cli to use the correct subscription and the tenant.

### Creating the Infrastructure

#### Usage
```
❯ bash setup.sh
-----------------------------------------------
| Security Deployment Azure FrontDoor and WAF |
-----------------------------------------------
Usage: setup.sh [options]

Options:

--project                    - Name of the Project [default: "security"]
--env                        - Name of the Environment {non-prod, prod}.
--rg                         - Name of the Azure Resource group to deploy the Resources and the ARM Spec
--location                   - Azure Location to do the deployment

e.g. setup.sh --project=security --env=dev --rg=dev-rg --location=eastus2

```

#### Instructions in Passing Arguments
##### --project
```
Name of the Project. The default value is security.
```
##### --env
```
[Mandatory] Name of the Environment. Allowed values are non-prod, prod. 
```
```
conf
└── setup.parameters.json.sample
└── non-prod.setup.parameters.json // actual parameters for non-prod goes here. Only available in the specific branch.
```
##### --rg
```
[Mandatory] Name of the Resource Group to do the deployment. This resource group should pre exist.
```

##### --location
```
[Mandatory] Azure Region to do the deployment.
```
#### Configuration
Sample Azure Resource Manager [Parameter file](conf/setup.parameters.json.sample)

```
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "project": {
            "value": ""
        },
        "environment": {
            "value": ""
        }
    }
}
```

For an example,
```
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "project": {
            "value": "security" // should be the same as --project flag passed to the script.
        },
        "environment": {
            "value": "non-prod" // should be the same as the --env flag passed to the script. This parameter file also should be saved in the folder related to the evironment.
        }
    }
}
```  
##### ❗ The ARM parameters file should be placed in conf folder, with the naming convention of `<env>.setup.parameters.json`. This should be the same as the --env input to the script
