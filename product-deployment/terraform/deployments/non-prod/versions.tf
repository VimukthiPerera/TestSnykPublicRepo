# -------------------------------------------------------------------------------------
#
# Copyright (c) 2020, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
#
# This software is the property of WSO2 Inc. and its suppliers, if any.
# Dissemination of any information or reproduction of any material contained
# herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
# You may not alter or remove any copyright or other notice from copies of this content.
#
# --------------------------------------------------------------------------------------

terraform {
  required_version = "= 1.0.3"
  backend "azurerm" {
  }

  required_providers {
    azurerm = "= 2.71"
    azuread = "= 1.2.2"
    random  = "= 2.2"
    azuredevops = {
      source  = "microsoft/azuredevops"
      version = "=0.1.0"
    }
  }
}
