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

project               = "security"
environment           = "non-prod"
location              = "eastus2"
padding               = "001"
shortened_project     = "sec"
shortened_environment = "np"
shortened_location    = "eus2"
shortened_padding     = "01"
application_name_main = "main"

resource_group_name = "rg-security-main-non-prod-eastus2-001"
subscription_name   = "security-non-prod-001"
subscription_id     = "7b001248-55ca-476d-8f00-7d0450a72391"
tenant_id           = "da76d684-740f-4d94-8717-9d5fb21dd1f9"

# Terraform State file Blog storage
backend_storage_account_name = "tfstatesecnonprod001"
backend_container_name       = "sentinel"

log_retention_in_days = "90"
# Specifies the Sku of the Log Analytics Workspace. 
log_analytics_workspace_sku = "PerGB2018"

## Storage account
account_name = "st-security-data-export"
account_replication_type = "RAGRS"
