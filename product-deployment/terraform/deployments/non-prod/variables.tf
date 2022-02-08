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

variable "project" {
  description = "The name of the project"
  type        = string
}

variable "environment" {
  description = "The name of the environment e.g. staging,prod"
  type        = string
}

variable "location" {
  description = "The Azure region to deploy"
  type        = string
}

variable "padding" {
  description = "Padding for the deployment"
  type        = string
}

variable "shortened_project" {
  description = "Shortened version of project"
  type        = string
}

variable "shortened_environment" {
  description = "Shortened version of environment"
  type        = string
}

variable "shortened_location" {
  description = "Shortened version of location"
  type        = string
}

variable "shortened_padding" {
  description = "Shortened version of padding"
  type        = string
}

variable "application_name_main" {
  description = "Main application name"
  type        = string
}

variable "private_endpoint_subnet_workload_name_acr" {
  description = "ACR private endpoint subnet workload name"
  type        = string
  default     = "acr"
}

variable "resource_group_name" {
  description = "The name of the Resource Group"
  type        = string
}

## Terraform storage 
variable "backend_storage_account_name" {
  description = "Terraform Backend Storage Account Name"
  type        = string
}

variable "backend_container_name" {
  description = "Terraform Backend Storage container Name"
  type        = string
}

variable "backend_key" {
  description = "Terraform Backend file name"
  type        = string
}

variable "subscription_name" {
  description = "The name of the Azure Subscription"
  type        = string
}

variable "subscription_id" {
  description = "The Azure subscription ID"
  type        = string
}

variable "tenant_id" {
  description = "The Azure subscription tenant ID"
  type        = string
}

variable "log_analytics_workspace_sku" {
  description = "The sku of the  AKS Cluster log analytics workspace"
  type        = string
  default     = "PerGB2018"
}

variable "log_retention_in_days" {
  description = "The log retention days of the  AKS Cluster"
  type        = string
}

variable "account_name" {
  description = "The name of the storage account"
  type        = string
}

variable "account_replication_type" {
  description = "The type of replication to use for this storage account"
  type        = string
}

# ARM template spec deployment
variable "template_spec_id" {
  description = "The Resource ID of the template spec with version"
  type        = string
}

variable "gmail_request_uri" {
  description = "The Gmail request endpoint URI"
  type        = string
  default     = "https://management.azure.com:443/subscriptions/7b001248-55ca-476d-8f00-7d0450a72391/resourceGroups/rg-security-main-non-prod-eastus2-001/providers/Microsoft.Web/connections/"
}

variable "blob_request_uri" {
  description = "The Blob request endpoint URI"
  type        = string
  default     = "https://management.azure.com:443/subscriptions/7b001248-55ca-476d-8f00-7d0450a72391/resourceGroups/rg-security-main-non-prod-eastus2-001/providers/Microsoft.Web/connections/"
}

variable "snow_request_uri" {
  description = "The Snow request endpoint URI"
  type        = string
  default     = "https://management.azure.com:443/subscriptions/7b001248-55ca-476d-8f00-7d0450a72391/resourceGroups/rg-security-main-non-prod-eastus2-001/providers/Microsoft.Web/connections/"
}
