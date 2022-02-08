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

# Configure the Azure Resource Manager Provider
provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  features {}
}

# Configure provider
provider "azuredevops" {
  org_service_url       = var.devops_org_service_url
  personal_access_token = var.devops_personal_access_token
}

# Create resource group
module "resource-group" {
  source           = "git::https://github.com/wso2-enterprise/azure-terraform-modules.git//modules/azurerm/Resource-Group?ref=v2.3.5"
  location         = var.location
  application_name = var.application_name_main
  default_tags     = local.default_tags
  environment      = var.environment
  padding          = var.padding
  project          = var.project
}

# Create Log Analytics Workspace
module "log_analytics_workspace" {
  source                      = "git::https://github.com/wso2-enterprise/azure-terraform-modules.git//modules/azurerm/Log-Analytics-Workspaces?ref=v2.3.5"
  project                     = var.project
  resource_group_name         = module.resource-group.resource_group_name
  default_tags                = local.default_tags
  location                    = var.location
  environment                 = var.environment
  log_analytics_workspace_sku = var.log_analytics_workspace_sku
  log_retention_in_days       = var.log_retention_in_days
  application_name            = var.application_name_main
  padding                     = var.padding
  depends_on                  = [module.resource-group]
}

# Deploy ARM Template Spec
module "arm_template_spec" {
  source                        = "git::https://github.com/wso2-enterprise/azure-terraform-modules.git//modules/azurerm/Resource-Group-Template-Spec-Deployment?ref=v2.5.1"
  project                       = var.project
  environment                   = var.environment
  template_spec_deployment_name = "arm-template-spec-deployment"
  resource_group_name           = module.resource-group.resource_group_name
  parameter_content = jsonencode({
    "project" = {
      value = var.project
    },
    "environment" = {
      value = var.environment
    },
    "location" = {
      value = var.location
    },
    "subscriptionId" = {
      value = var.subscription_id
    },
    "tenantId" = {
      value = var.tenant_id
    },
    "gmailRequestURI" = {
      value = var.gmail_request_uri
    },
    "blobRequestURI" = {
      value = var.blob_request_uri
    },
    "storageAccountName" = {
      value = var.account_name
    },
    "snowRequestURI" = {
      value = var.snow_request_uri
    }
  })
  template_spec_id = var.template_spec_id
  depends_on = [
    module.resource-group
  ]
}

# Add SecurityInsights solution
resource "azurerm_log_analytics_solution" "la_opf_solution_sentinel" {
  solution_name         = "SecurityInsights"
  location              = var.location
  resource_group_name   = module.resource-group.resource_group_name
  workspace_resource_id = module.log_analytics_workspace.log_analytics_workspace_id
  workspace_name        = module.log_analytics_workspace.log_analytics_workspace_name
  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityInsights"
  }
  depends_on = [module.log_analytics_workspace]
  tags       = local.default_tags
}

# Create Storage account

module "storage_account" {
  source                   = "git::https://github.com/wso2-enterprise/azure-terraform-modules.git//modules/azurerm/Storage-Account-Blob?ref=v2.3.5"
  resource_group_name      = module.resource-group.resource_group_name
  default_tags             = local.default_tags
  location                 = var.location
  shortened_environment    = var.shortened_environment
  shortened_project        = var.shortened_project
  shortened_location       = var.shortened_location
  shortened_padding        = var.shortened_padding
  account_replication_type = var.account_replication_type
  application_name         = "sntlde"
}

#####################
## Data Connectors ##
#####################

# Azure Defender
resource "azurerm_sentinel_data_connector_azure_security_center" "sdc_azure_security_center" {
  name                       = "sdc_azure_security_center"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Azure Active Directory
/* 
resource "azurerm_sentinel_data_connector_azure_advanced_threat_protection" "sdc_azure_advanced_threat_protection" {
  name                       = "sdc_advanced_threat_protection"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
} */

# Azure Active Directory - Identity Protection
resource "azurerm_sentinel_data_connector_azure_active_directory" "sdc_azure_active_directory" {
  name                       = "sdc_active_directory"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Threat Intelligence Platforms (Preview)
resource "azurerm_sentinel_data_connector_threat_intelligence" "sdc_threat_intelligence" {
  name                       = "sdc_threat_intelligence"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

################
## Logic apps ##
################

# Added via ARM

#####################
## Analytics rules ##
#####################

# Fusion - High
# TBM - Automated response
resource "azurerm_sentinel_alert_rule_fusion" "sdr_advanced_multistage_attack_detection" {
  name                       = "Advanced Multistage Attack Detection"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  alert_rule_template_guid   = "f71aba3d-28fb-450b-b192-4e76a83015c8"
  enabled                    = true
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Microsoft Security - High
# TBM - Automated response
resource "azurerm_sentinel_alert_rule_ms_security_incident" "sdr_create_incidents_based_on_aad_ip_alerts" {
  name                       = "sdr_create_incidents_based_on_aad_ip_alerts"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  product_filter             = "Azure Active Directory Identity Protection"
  display_name               = "Create incidents based on Azure Active Directory Identity Protection alerts"
  description                = "Create incidents based on all alerts generated in Azure Active Directory Identity Protection"
  enabled                    = true
  severity_filter            = ["High", "Medium", "Low", "Informational"]
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_ms_security_incident" "sdr_create_incidents_based_on_azure_security_center_alerts" {
  name                       = "sdr_create_incidents_based_on_azure_security_center_alerts"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  product_filter             = "Azure Security Center"
  display_name               = "Create incidents based on Azure Security Center alerts"
  description                = "Create incidents based on all alerts generated in Azure Security Center"
  enabled                    = true
  severity_filter            = ["High", "Medium", "Low", "Informational"]
  depends_on                 = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Scheduled - High
# TBM - Set logic rule(custom details), Automated response, Incident grouping(_ResourceId)
/* resource "azurerm_sentinel_alert_rule_scheduled" "sdr_wso2_high_number_of_aks_pods_deployment_dos_attack" {
  name                       = "sdr_wso2_high_number_of_aks_pods_deployment_dos_attack"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "[WSO2] High Number of AKS Pods deployment- DOS Attack"
  description                = "This query is to detect a high number of AKS PODs created within a namespace."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let threshold = 80;
AzureDiagnostics
| where Category == "kube-controller-manager"
| where log_s has "'SuccessfulCreate' Created pod:"
| parse log_s with * "Created pod: " POD
| project TimeGenerated, ResourceGroup, POD, ccpNamespace_s, _ResourceId
| summarize StartTime = min(TimeGenerated), Count = count() by ccpNamespace_s, ResourceGroup, _ResourceId
| where Count >=["threshold"]
| extend Timestamp = StartTime, NameSpaceCustomEntity = ccpNamespace_s, ResourceGroup, _ResourceId
QUERY
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Execution", "Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account"] # _ResourceID is not available
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}
 */
# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_brute_force_attack_against_azure_portal" {
  name                       = "sdr_brute_force_attack_against_azure_portal"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Brute force attack against Azure Portal"
  description                = "Identifies evidence of brute force activity against Azure Portal by highlighting multiple authentication failures and by a successful authentication within a given time window. (The query does not enforce any sequence - eg requiring the successful authentication to occur last.) Default Failure count is 5, Default Success count is 1 and default Time Window is 20 minutes. References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let failureCountThreshold = 5;
let successCountThreshold = 1;
let authenticationWindow = 20m;
let aadFunc = (tableName:string){
table(tableName)
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
| where AppDisplayName has "Azure Portal"
// Split out failure versus non-failure types
| extend FailureOrSuccess = iff(ResultType in ("0", "50125", "50140", "70043", "70044"), "Success", "Failure")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPAddress = make_set(IPAddress), make_set(OS), make_set(Browser), make_set(City),
make_set(State), make_set(Region),make_set(ResultType), FailureCount = countif(FailureOrSuccess=="Failure"), SuccessCount = countif(FailureOrSuccess=="Success")
by bin(TimeGenerated, authenticationWindow), UserDisplayName, UserPrincipalName, AppDisplayName, Type
| where FailureCount >= failureCountThreshold and SuccessCount >= successCountThreshold
| mvexpand IPAddress
| extend IPAddress = tostring(IPAddress)
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_correlate_unfamiliar_sign_in_properties_and_atypical_travel_alerts" {
  name                       = "sdr_correlate_unfamiliar_sign_in_properties_and_atypical_travel_alerts"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Correlate Unfamiliar sign-in properties and atypical travel alerts"
  description                = "When a user has both an Unfamiliar sign-in properties alert and an Atypical travel alert within 20 minutes, the alert should be handled with a higher severity."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let Alert1 =
SecurityAlert
| where AlertName == "Unfamiliar sign-in properties"
| extend UserPrincipalName = tostring(parse_json(ExtendedProperties).["User Account"])
| extend Alert1Time = TimeGenerated
| extend Alert1 = AlertName
| extend Alert1Severity = AlertSeverity
;
let Alert2 =
SecurityAlert
| where AlertName == "Atypical travel"
| extend UserPrincipalName = tostring(parse_json(ExtendedProperties).["User Account"])
| extend Alert2Time = TimeGenerated
| extend Alert2 = AlertName
| extend Alert2Severity = AlertSeverity
| extend CurrentLocation = strcat(tostring(parse_json(tostring(parse_json(Entities)[1].Location)).CountryCode), "|", tostring(parse_json(tostring(parse_json(Entities)[1].Location)).State), "|", tostring(parse_json(tostring(parse_json(Entities)[1].Location)).City))
| extend PreviousLocation = strcat(tostring(parse_json(tostring(parse_json(Entities)[2].Location)).CountryCode), "|", tostring(parse_json(tostring(parse_json(Entities)[2].Location)).State), "|", tostring(parse_json(tostring(parse_json(Entities)[2].Location)).City))
| extend CurrentIPAddress = tostring(parse_json(Entities)[1].Address)
| extend PreviousIPAddress = tostring(parse_json(Entities)[2].Address)
;
Alert1
| join kind=inner Alert2 on UserPrincipalName
| where abs(datetime_diff('minute', Alert1Time, Alert2Time)) <=10
| extend TimeDelta = Alert1Time - Alert2Time
| project UserPrincipalName, Alert1, Alert1Time, Alert1Severity, Alert2, Alert2Time, Alert2Severity, TimeDelta, CurrentLocation, PreviousLocation, CurrentIPAddress, PreviousIPAddress
| extend AccountCustomEntity = UserPrincipalName
| extend IPCustomEntity = CurrentIPAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_explicit_mfa_deny" {
  name                       = "sdr_explicit_mfa_deny"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Explicit MFA Deny"
  description                = "User explicitly denies MFA push, indicating that login was not expected and the account's password may be compromised."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let aadFunc = (tableName:string){
table(tableName)
| where ResultType == 500121
| where Status has "MFA Denied; user declined the authentication"
| extend Type = Type
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, URLCustomEntity = ClientAppUsed
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT2H"
  query_period               = "PT2H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_first_access_credential_added_to_app_or_sp_where_no_credential_was_present" {
  name                       = "sdr_first_access_credential_added_to_app_or_sp_where_no_credential_was_present"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "First access credential added to Application or Service Principal where no credential was present"
  description                = "This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where there was no previous verify KeyCredential associated. If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential. Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
| where Result =~ "success"
| mv-expand target = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set == "[]"
| parse new_value_set with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify" or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Azure Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_barium_domains" {
  name                       = "sdr_known_barium_domains"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known Barium domains"
  description                = "Identifies a match across various data feeds for domains IOCs related to the Barium activity group. References: https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = dynamic(["0.ns1.dns-info.gq", "1.ns1.dns-info.gq", "10.ns1.dns-info.gq", "102.ns1.dns-info.gq",
"104.ns1.dns-info.gq", "11.ns1.dns-info.gq", "110.ns1.dns-info.gq", "115.ns1.dns-info.gq", "116.ns1.dns-info.gq",
"117.ns1.dns-info.gq", "118.ns1.dns-info.gq", "12.ns1.dns-info.gq", "120.ns1.dns-info.gq", "122.ns1.dns-info.gq",
"123.ns1.dns-info.gq", "128.ns1.dns-info.gq", "13.ns1.dns-info.gq", "134.ns1.dns-info.gq", "135.ns1.dns-info.gq",
"138.ns1.dns-info.gq", "14.ns1.dns-info.gq", "144.ns1.dns-info.gq", "15.ns1.dns-info.gq", "153.ns1.dns-info.gq",
"157.ns1.dns-info.gq", "16.ns1.dns-info.gq", "17.ns1.dns-info.gq", "18.ns1.dns-info.gq", "19.ns1.dns-info.gq",
"1a9604fa.ns1.feedsdns.com", "1c7606b6.ns1.steamappstore.com", "2.ns1.dns-info.gq", "20.ns1.dns-info.gq",
"201.ns1.dns-info.gq", "202.ns1.dns-info.gq", "204.ns1.dns-info.gq", "207.ns1.dns-info.gq", "21.ns1.dns-info.gq",
"210.ns1.dns-info.gq", "211.ns1.dns-info.gq", "216.ns1.dns-info.gq", "22.ns1.dns-info.gq", "220.ns1.dns-info.gq",
"223.ns1.dns-info.gq", "23.ns1.dns-info.gq", "24.ns1.dns-info.gq", "25.ns1.dns-info.gq", "26.ns1.dns-info.gq",
"27.ns1.dns-info.gq", "28.ns1.dns-info.gq", "29.ns1.dns-info.gq", "3.ns1.dns-info.gq", "30.ns1.dns-info.gq",
"31.ns1.dns-info.gq", "32.ns1.dns-info.gq", "33.ns1.dns-info.gq", "34.ns1.dns-info.gq", "35.ns1.dns-info.gq",
"36.ns1.dns-info.gq", "37.ns1.dns-info.gq", "39.ns1.dns-info.gq", "3d6fe4b2.ns1.steamappstore.com",
"4.ns1.dns-info.gq", "40.ns1.dns-info.gq", "42.ns1.dns-info.gq", "43.ns1.dns-info.gq", "44.ns1.dns-info.gq",
"45.ns1.dns-info.gq", "46.ns1.dns-info.gq", "48.ns1.dns-info.gq", "5.ns1.dns-info.gq", "50.ns1.dns-info.gq",
"50417.service.gstatic.dnset.com", "51.ns1.dns-info.gq", "52.ns1.dns-info.gq", "53.ns1.dns-info.gq",
"54.ns1.dns-info.gq", "55.ns1.dns-info.gq", "56.ns1.dns-info.gq", "57.ns1.dns-info.gq", "58.ns1.dns-info.gq",
"6.ns1.dns-info.gq", "60.ns1.dns-info.gq", "62.ns1.dns-info.gq", "63.ns1.dns-info.gq", "64.ns1.dns-info.gq",
"65.ns1.dns-info.gq", "67.ns1.dns-info.gq", "7.ns1.dns-info.gq", "70.ns1.dns-info.gq", "71.ns1.dns-info.gq",
"73.ns1.dns-info.gq", "77.ns1.dns-info.gq", "77075.service.gstatic.dnset.com", "7c1947fa.ns1.steamappstore.com",
"8.ns1.dns-info.gq", "81.ns1.dns-info.gq", "86.ns1.dns-info.gq", "87.ns1.dns-info.gq", "9.ns1.dns-info.gq",
"94343.service.gstatic.dnset.com", "9939.service.gstatic.dnset.com", "aa.ns.mircosoftdoc.com",
"aaa.feeds.api.ns1.feedsdns.com", "aaa.googlepublic.feeds.ns1.dns-info.gq",
"aaa.resolution.174547._get.cache.up.sourcedns.tk", "acc.microsoftonetravel.com",
"accounts.longmusic.com", "admin.dnstemplog.com", "agent.updatenai.com",
"alibaba.zzux.com", "api.feedsdns.com", "app.portomnail.com", "asia.updatenai.com",
"battllestategames.com", "bguha.serveuser.com", "binann-ce.com", "bing.dsmtp.com",
"blog.cdsend.xyz", "brives.minivineyapp.com", "bsbana.dynamic-dns.net",
"californiaforce.000webhostapp.com", "californiafroce.000webhostapp.com",
"cdn.freetcp.com", "cdsend.xyz", "cipla.zzux.com", "cloudfeeddns.com", "comcleanner.info",
"cs.microsoftsonline.net", "dns-info.gq", "dns05.cf", "dns22.ml", "dns224.com",
"dnsdist.org", "dnstemplog.com", "doc.mircosoftdoc.com", "dropdns.com",
"eshop.cdn.freetcp.com", "exchange.dumb1.com", "exchange.misecure.com", "exchange.mrbasic.com",
"facebookdocs.com", "facebookint.com", "facebookvi.com", "feed.ns1.dns-info.gq", "feedsdns.com",
"firejun.freeddns.com", "ftp.dns-info.dyndns.pro", "goallbandungtravel.com", "goodhk.azurewebsites.net",
"googlepublic.feed.ns1.dns-info.gq", "gp.spotifylite.cloud", "gskytop.com", "gstatic.dnset.com",
"gxxservice.com", "helpdesk.cdn.freetcp.com", "id.serveuser.com", "infestexe.com", "item.itemdb.com",
"m.mircosoftdoc.com", "mail.transferdkim.xyz", "mcafee.updatenai.com", "mecgjm.mircosoftdoc.com",
"microdocs.ga", "microsock.website", "microsocks.net", "microsoft.sendsmtp.com",
"microsoftbook.dns05.com", "microsoftcontactcenter.com", "microsoftdocs.dns05.com", "microsoftdocs.ml",
"microsoftonetravel.com", "microsoftonlines.net", "microsoftprod.com", "microsofts.dns1.us", "microsoftsonline.net",
"minivineyapp.com", "mircosoftdoc.com", "mircosoftdocs.com", "mlcrosoft.ninth.biz", "mlcrosoft.site",
"mm.portomnail.com", "msdnupdate.com", "msecdn.cloud", "mtnl1.dynamic-dns.net", "ns.gstatic.dnset.com",
"ns.microsoftprod.com", "ns.steamappstore.com", "ns1.cdn.freetcp.com", "ns1.comcleanner.info", "ns1.dns-info.gq",
"ns1.dns05.cf", "ns1.dnstemplog.com", "ns1.dropdns.com", "ns1.microsoftonetravel.com",
"ns1.microsoftonlines.net", "ns1.microsoftprod.com", "ns1.microsoftsonline.net", "ns1.mlcrosoft.site",
"ns1.teams.wikaba.com", "ns1.windowsdefende.com", "ns2.comcleanner.info", "ns2.dnstemplog.com",
"ns2.microsoftonetravel.com", "ns2.microsoftprod.com", "ns2.microsoftsonline.net", "ns2.mlcrosoft.site",
"ns2.windowsdefende.com", "ns3.microsoftprod.com", "ns3.mlcrosoft.site", "nutrition.mrbasic.com",
"nutrition.youdontcare.com", "online.mlcrosoft.site", "online.msdnupdate.com", "outlookservce.site",
"owa.jetos.com", "owa.otzo.com", "pornotime.co", "portomnail.com",
"post.1a0.066e063ac.7c1947fa.ns1.steamappstore.com", "pricingdmdk.com", "prod.microsoftprod.com",
"product.microsoftprod.com", "ptcl.yourtrap.com", "query.api.sourcedns.tk", "rb.itemdb.com", "redditcdn.com",
"rss.otzo.com", "secure.msdnupdate.com", "service.dns22.ml", "service.gstatic.dnset.com", "service04.dns04.com",
"settings.teams.wikaba.com", "sip.outlookservce.site", "sixindent.epizy.com", "soft.msdnupdate.com", "sourcedns.ml",
"sourcedns.tk", "sport.msdnupdate.com", "spotifylite.cloud", "static.misecure.com", "steamappstore.com",
"store.otzo.com", "survey.outlookservce.site", "team.itemdb.com", "temp221.com", "test.microsoftprod.com",
"thisisaaa.000webhostapp.com", "token.dns04.com", "token.dns05.com", "transferdkim.xyz",
"travelsanignacio.com", "update08.com", "updated08.com", "updatenai.com", "wantforspeed.com",
"web.mircosoftdoc.com", "webmail.pornotime.co", "webwhois.team.itemdb.com", "windowsdefende.com", "wnswindows.com",
"ashcrack.freetcp.com", "battllestategames.com", "binannce.com", "cdsend.xyz", "comcleanner.info", "microsock.website",
"microsocks.net", "microsoftsonline.net", "mlcrosoft.site", "notify.serveuser.com", "ns1.microsoftprod.com",
"ns2.microsoftprod.com", "pricingdmdk.com", "steamappstore.com", "update08.com", "wnswindows.com",
"youtube.dns05.com", "z1.zalofilescdn.com", "z2.zalofilescdn.com", "zalofilescdn.com"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where DNSName in~ (DomainNames)
| extend Account = SourceUserID, Computer = DeviceName, IPAddress = DestinationIP
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = ClientIP
),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = RemoteIp
),
(
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| where RemoteUrl in~ (DomainNames)
| extend IPAddress = RemoteIP
| extend Computer = DeviceName
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPAddress = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_barium_ip" {
  name                       = "sdr_known_barium_ip"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known Barium IP"
  description                = "Identifies a match across various data feeds for IP IOCs related to the Barium activity group. References: https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer'"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let IPList = dynamic(["216.24.185.74", "107.175.189.159", "192.210.132.102", "67.230.163.214",
"199.19.110.240", "107.148.130.176", "154.212.129.218", "172.86.75.54", "45.61.136.199",
"149.28.150.195", "108.61.214.194", "144.202.98.198", "149.28.84.98", "103.99.209.78",
"45.61.136.2", "176.122.162.149", "192.3.80.245", "149.28.23.32", "107.182.18.149", "107.174.45.134",
"149.248.18.104", "65.49.192.74", "156.255.2.154", "45.76.6.149", "8.9.11.130", "140.238.27.255",
"107.182.24.70", "176.122.188.254", "192.161.161.108", "64.64.234.24", "104.224.185.36",
"104.233.224.227", "104.36.69.105", "119.28.139.120", "161.117.39.130", "66.42.100.42", "45.76.31.159",
"149.248.8.134", "216.24.182.48", "66.42.103.222", "218.89.236.11", "180.150.227.249", "47.75.80.23",
"124.156.164.19", "149.248.62.83", "150.109.76.174", "222.209.187.207", "218.38.191.38",
"119.28.226.59", "66.42.98.220", "74.82.201.8", "173.242.122.198", "45.32.130.72", "89.35.178.10",
"89.43.60.113"]);
(union isfuzzy=true
(CommonSecurityLog
| where isnotempty(SourceIP) or isnotempty(DestinationIP)
| where SourceIP in (IPList) or DestinationIP in (IPList) or Message has_any (IPList)
| extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "Message")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by SourceIP, DestinationIP, DeviceProduct, DeviceAction, Message, Protocol, SourcePort, DestinationPort, DeviceAddress, DeviceName, IPMatch
| extend timestamp = StartTimeUtc, IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "IP in Message Field")
),
(OfficeActivity
|extend SourceIPAddress = ClientIP, Account = UserId
| where SourceIPAddress in (IPList)
| extend timestamp = TimeGenerated , IPCustomEntity = SourceIPAddress , AccountCustomEntity = Account
),
(DnsEvents
| extend DestinationIPAddress = IPAddresses, Host = Computer
| where DestinationIPAddress has_any (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
),
(VMConnection
| where isnotempty(SourceIp) or isnotempty(DestinationIp)
| where SourceIp in (IPList) or DestinationIp in (IPList)
| extend IPMatch = case( SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated , IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"), Host = Computer
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend SourceIP = EventDetail.[9].["#text"], DestinationIP = EventDetail.[14].["#text"]
| where SourceIP in (IPList) or DestinationIP in (IPList)
| extend IPMatch = case( SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated, AccountCustomEntity = UserName, HostCustomEntity = Computer , IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
),
(WireData
| where isnotempty(RemoteIP)
| where RemoteIP in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP, HostCustomEntity = Computer
),
(SigninLogs
| where isnotempty(IPAddress)
| where IPAddress in (IPList)
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
),
(AADNonInteractiveUserSignInLogs
| where isnotempty(IPAddress)
| where IPAddress in (IPList)
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
),
(W3CIISLog
| where isnotempty(cIP)
| where cIP in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName
),
(AzureActivity
| where isnotempty(CallerIpAddress)
| where CallerIpAddress in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = CallerIpAddress, AccountCustomEntity = Caller
),
(
AWSCloudTrail
| where isnotempty(SourceIpAddress)
| where SourceIpAddress in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName
),
(
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| where RemoteIP in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP, HostCustomEntity = DeviceName
)
)
QUERY
  query_frequency            = "PT8H"
  query_period               = "PT8H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT4H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_cerium_domain_and_hashes" {
  name                       = "sdr_known_cerium_domain_and_hashes"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known CERIUM domains and hashes"
  description                = "CERIUM malicious webserver and hash values for maldocs and malware. Matches domain name IOCs related to the CERIUM activity group with CommonSecurityLog, DnsEvents, and VMConnection dataTypes."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = "miniodaum.ml";
let SHA256Hash = dynamic (["53f5773bbfbfbee660989d135c042c9f6f69024b9a4b65bdc0dfd44771762257", "0897c80df8b80b4c49bf1ccf876f5f782849608b830c3b5cb3ad212dc3e19eff"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where isnotempty(FileHash)
| where FileHash in (SHA256Hash) or DNSName =~ DomainNames
| extend Account = SourceUserID, Computer = DeviceName, IPAddress = SourceIP
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName =~ DomainNames
| extend IPAddress = ClientIP
),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName =~ DomainNames
| extend IPAddress = RemoteIp
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPAddress = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_gallium_domain_and_hashes" {
  name                       = "sdr_known_gallium_domain_and_hashes"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known GALLIUM domains and hashes"
  description                = "GALLIUM command and control domains and hash values for tools and malware used by GALLIUM. Matches domain name IOCs related to the GALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes. References: https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = dynamic(["asyspy256.ddns.net","hotkillmail9sddcc.ddns.net","rosaf112.ddns.net","cvdfhjh1231.myftp.biz","sz2016rose.ddns.net","dffwescwer4325.myftp.biz","cvdfhjh1231.ddns.net"]);
let SHA1Hash = dynamic (["53a44c2396d15c3a03723fa5e5db54cafd527635", "9c5e496921e3bc882dc40694f1dcc3746a75db19", "aeb573accfd95758550cf30bf04f389a92922844", "79ef78a797403a4ed1a616c68e07fff868a8650a", "4f6f38b4cec35e895d91c052b1f5a83d665c2196", "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d", "e841a63e47361a572db9a7334af459ddca11347a", "c28f606df28a9bc8df75a4d5e5837fc5522dd34d", "2e94b305d6812a9f96e6781c888e48c7fb157b6b", "dd44133716b8a241957b912fa6a02efde3ce3025", "8793bf166cb89eb55f0593404e4e933ab605e803", "a39b57032dbb2335499a51e13470a7cd5d86b138", "41cc2b15c662bc001c0eb92f6cc222934f0beeea", "d209430d6af54792371174e70e27dd11d3def7a7", "1c6452026c56efd2c94cea7e0f671eb55515edb0", "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a", "4923d460e22fbbf165bbbaba168e5a46b8157d9f", "f201504bd96e81d0d350c3a8332593ee1c9e09de", "ddd2db1127632a2a52943a2fe516a2e7d05d70d2"]);
let SHA256Hash = dynamic (["9ae7c4a4e1cfe9b505c3a47e66551eb1357affee65bfefb0109d02f4e97c06dd", "7772d624e1aed327abcd24ce2068063da0e31bb1d5d3bf2841fc977e198c6c5b", "657fc7e6447e0065d488a7db2caab13071e44741875044f9024ca843fe4e86b5", "2ef157a97e28574356e1d871abf75deca7d7a1ea662f38b577a06dd039dbae29", "52fd7b90d7144ac448af4008be639d4d45c252e51823f4311011af3207a5fc77", "a370e47cb97b35f1ae6590d14ada7561d22b4a73be0cb6df7e851d85054b1ac3", "5bf80b871278a29f356bd42af1e35428aead20cd90b0c7642247afcaaa95b022", "6f690ccfd54c2b02f0c3cb89c938162c10cbeee693286e809579c540b07ed883", "3c884f776fbd16597c072afd81029e8764dd57ee79d798829ca111f5e170bd8e", "1922a419f57afb351b58330ed456143cc8de8b3ebcbd236d26a219b03b3464d7", "fe0e4ef832b62d49b43433e10c47dc51072959af93963c790892efc20ec422f1", "7ce9e1c5562c8a5c93878629a47fe6071a35d604ed57a8f918f3eadf82c11a9c", "178d5ee8c04401d332af331087a80fb4e5e2937edfba7266f9be34a5029b6945", "51f70956fa8c487784fd21ab795f6ba2199b5c2d346acdeef1de0318a4c729d9", "889bca95f1a69e94aaade1e959ed0d3620531dc0fc563be9a8decf41899b4d79", "332ddaa00e2eb862742cb8d7e24ce52a5d38ffb22f6c8bd51162bd35e84d7ddf", "44bcf82fa536318622798504e8369e9dcdb32686b95fcb44579f0b4efa79df08", "63552772fdd8c947712a2cff00dfe25c7a34133716784b6d486227384f8cf3ef", "056744a3c371b5938d63c396fe094afce8fb153796a65afa5103e1bffd7ca070"]);
let SigNames = dynamic(["TrojanDropper:Win32/BlackMould.A!dha", "Trojan:Win32/BlackMould.B!dha", "Trojan:Win32/QuarkBandit.A!dha", "Trojan:Win32/Sidelod.A!dha"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where isnotempty(FileHash)
| where FileHash in (SHA256Hash) or DNSName in~ (DomainNames)
| extend Account = SourceUserID, Computer = DeviceName, IPAddress = SourceIP
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = ClientIP
),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = RemoteIp
),
(Event
//This query uses sysmon data depending on table name used this may need updataing
| where Source == "Microsoft-Windows-Sysmon"
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Hashes = EventDetail.[16].["#text"]
| parse Hashes with * 'SHA1=' SHA1 ',' *
| where isnotempty(Hashes)
| where Hashes in (SHA1Hash)
| extend Account = UserName
),
(SecurityAlert
| where Entities has_any (SigNames)
| extend Computer = tostring(parse_json(Entities)[0].HostName)
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPAddress = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_iridium_ip" {
  name                       = "sdr_known_iridium_ip"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known IRIDIUM IP"
  description                = "IRIDIUM command and control IP. Identifies a match across various data feeds for IP IOCs related to the IRIDIUM activity group."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let IPList = dynamic(["154.223.45.38","185.141.207.140","185.234.73.19","216.245.210.106","51.91.48.210","46.255.230.229"]);
(union isfuzzy=true
(CommonSecurityLog
| where isnotempty(SourceIP) or isnotempty(DestinationIP)
| where SourceIP in (IPList) or DestinationIP in (IPList) or Message has_any (IPList)
| extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "Message")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by SourceIP, DestinationIP, DeviceProduct, DeviceAction, Message, Protocol, SourcePort, DestinationPort, DeviceAddress, DeviceName, IPMatch
| extend timestamp = StartTimeUtc, IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "IP in Message Field")
),
(OfficeActivity
|extend SourceIPAddress = ClientIP, Account = UserId
| where SourceIPAddress in (IPList)
| extend timestamp = TimeGenerated , IPCustomEntity = SourceIPAddress , AccountCustomEntity = Account
),
(DnsEvents
| extend DestinationIPAddress = IPAddresses, Host = Computer
| where DestinationIPAddress has_any (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
),
(VMConnection
| where isnotempty(SourceIp) or isnotempty(DestinationIp)
| where SourceIp in (IPList) or DestinationIp in (IPList)
| extend IPMatch = case( SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated , IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"), Host = Computer
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend SourceIP = EventDetail.[9].["#text"], DestinationIP = EventDetail.[14].["#text"]
| where SourceIP in (IPList) or DestinationIP in (IPList)
| extend IPMatch = case( SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated, AccountCustomEntity = UserName, HostCustomEntity = Computer , IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
),
(SigninLogs
| where isnotempty(IPAddress)
| where IPAddress in (IPList)
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
),
(AADNonInteractiveUserSignInLogs
| where isnotempty(IPAddress)
| where IPAddress in (IPList)
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
),
(W3CIISLog
| where isnotempty(cIP)
| where cIP in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName
),
(AzureActivity
| where isnotempty(CallerIpAddress)
| where CallerIpAddress in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = CallerIpAddress, AccountCustomEntity = Caller
),
(
AWSCloudTrail
| where isnotempty(SourceIpAddress)
| where SourceIpAddress in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName
),
(
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (IPList)
| extend DestinationIP = DestinationHost
| extend IPCustomEntity = SourceHost
),
(
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallNetworkRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (IPList)
| extend DestinationIP = DestinationHost
| extend IPCustomEntity = SourceHost
)
)
QUERY
  query_frequency            = "PT8H"
  query_period               = "PT8H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT4H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_phosphorus_group_domains_ip" {
  name                       = "sdr_known_phosphorus_group_domains_ip"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known PHOSPHORUS group domains/IP"
  description                = "Matches domain name IOCs related to Phosphorus group activity with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes. References: https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY

let DomainNames = dynamic(["yahoo-verification.org","support-servics.com","verification-live.com","com-mailbox.com","com-myaccuants.com","notification-accountservice.com",
"accounts-web-mail.com","customer-certificate.com","session-users-activities.com","user-profile-credentials.com","verify-linke.com","support-servics.net","verify-linkedin.net",
"yahoo-verification.net","yahoo-verify.net","outlook-verify.net","com-users.net","verifiy-account.net","te1egram.net","account-verifiy.net","myaccount-services.net",
"com-identifier-servicelog.name","microsoft-update.bid","outlook-livecom.bid","update-microsoft.bid","documentsfilesharing.cloud","com-microsoftonline.club",
"confirm-session-identifier.info","session-management.info","confirmation-service.info","document-share.info","broadcast-news.info","customize-identity.info","webemail.info",
"com-identifier-servicelog.info","documentsharing.info","notification-accountservice.info","identifier-activities.info","documentofficupdate.info","recoveryusercustomer.info",
"serverbroadcast.info","account-profile-users.info","account-service-management.info","accounts-manager.info","activity-confirmation-service.info","com-accountidentifier.info",
"com-privacy-help.info","com-sessionidentifier.info","com-useraccount.info","confirmation-users-service.info","confirm-identity.info","confirm-session-identification.info",
"continue-session-identifier.info","customer-recovery.info","customers-activities.info","elitemaildelivery.info","email-delivery.info","identify-user-session.info",
"message-serviceprovider.info","notificationapp.info","notification-manager.info","recognized-activity.info","recover-customers-service.info","recovery-session-change.info",
"service-recovery-session.info","service-session-continue.info","session-mail-customers.info","session-managment.info","session-verify-user.info","shop-sellwear.info",
"supportmailservice.info","terms-service-notification.info","user-activity-issues.info","useridentity-confirm.info","users-issue-services.info","verify-user-session.info",
"login-gov.info","notification-signal-agnecy.info","notifications-center.info","identifier-services-sessions.info","customers-manager.info","session-manager.info",
"customer-managers.info","confirmation-recovery-options.info","service-session-confirm.info","session-recovery-options.info","services-session-confirmation.info",
"notification-managers.info","activities-services-notification.info","activities-recovery-options.info","activity-session-recovery.info","customers-services.info",
"sessions-notification.info","download-teamspeak.info","services-issue-notification.info","microsoft-upgrade.mobi","broadcastnews.pro","mobile-messengerplus.network"]);
let IPList = dynamic(["51.91.200.147"]);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| extend MessageIP = extract(IPRegex, 0, Message)
| extend RequestURLIP = extract(IPRegex, 0, Message)
| where (isnotempty(SourceIP) and SourceIP in (IPList)) or (isnotempty(DestinationIP) and DestinationIP in (IPList))
or (isnotempty(DNSName) and DNSName in~ (DomainNames)) or (isnotempty(DestinationHostName) and DestinationHostName in~ (DomainNames)) or (isnotempty(RequestURL) and (RequestURL has_any (DomainNames) or RequestURLIP in (IPList)))
or (isnotempty(Message) and MessageIP in (IPList))
| extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", MessageIP in (IPList), "Message", RequestURLIP in (IPList), "RequestUrl", "NoMatch")
| extend timestamp = TimeGenerated , IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP,IPMatch == "Message", MessageIP,
IPMatch == "RequestUrl", RequestURLIP,"NoMatch"), Account = SourceUserID, Host = DeviceName
),
(DnsEvents
| extend DestinationIPAddress = IPAddresses, DNSName = Name, Host = Computer
| where DestinationIPAddress in (IPList) or DNSName in~ (DomainNames)
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(SourceIp) or isnotempty(DestinationIp) or isnotempty(DNSName)
| where SourceIp in (IPList) or DestinationIp in (IPList) or DNSName in~ (DomainNames)
| extend IPMatch = case( SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated , IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"), Host = Computer),
(OfficeActivity
| extend SourceIPAddress = ClientIP, Account = UserId
| where SourceIPAddress in (IPList)
| extend timestamp = TimeGenerated , IPCustomEntity = SourceIPAddress , AccountCustomEntity = Account),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPCustomEntity = ClientIP),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPCustomEntity = SourceHost
)
)
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_phosphorus_group_domains_ip_october_2020" {
  name                       = "sdr_known_phosphorus_group_domains_ip_october_2020"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known PHOSPHORUS group domains/IP - October 2020"
  description                = "Matches IOCs related to PHOSPHORUS group activity published October 2020 with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes. References:"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = dynamic(["de-ma.online", "g20saudi.000webhostapp.com", "ksat20.000webhostapp.com"]);
let EmailAddresses = dynamic(["munichconference1962@gmail.com","munichconference@outlook.de", "munichconference@outlook.com", "t20saudiarabia@gmail.com", "t20saudiarabia@hotmail.com", "t20saudiarabia@outlook.sa"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| extend MessageIP = extract(IPRegex, 0, Message)
| extend RequestURLIP = extract(IPRegex, 0, Message)
| where (isnotempty(DNSName) and DNSName has_any (DomainNames))
or (isnotempty(DestinationHostName) and DestinationHostName has_any (DomainNames))
or (isnotempty(RequestURL) and (RequestURL has_any (DomainNames)))
| extend timestamp = TimeGenerated , AccountCustomEntity = SourceUserID, HostCustomEntity = DeviceName
),
(DnsEvents
| extend DestinationIPAddress = IPAddresses, DNSName = Name, Host = Computer
| where DNSName has_any (DomainNames)
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName has_any (DomainNames)
| extend timestamp = TimeGenerated , HostCustomEntity = Computer),
(SecurityAlert
| where ProviderName =~ 'OATP'
| extend UPN = case(isnotempty(parse_json(Entities)[0].Upn), parse_json(Entities)[0].Upn,
isnotempty(parse_json(Entities)[1].Upn), parse_json(Entities)[1].Upn,
isnotempty(parse_json(Entities)[2].Upn), parse_json(Entities)[2].Upn,
isnotempty(parse_json(Entities)[3].Upn), parse_json(Entities)[3].Upn,
isnotempty(parse_json(Entities)[4].Upn), parse_json(Entities)[4].Upn,
isnotempty(parse_json(Entities)[5].Upn), parse_json(Entities)[5].Upn,
isnotempty(parse_json(Entities)[6].Upn), parse_json(Entities)[6].Upn,
isnotempty(parse_json(Entities)[7].Upn), parse_json(Entities)[7].Upn,
isnotempty(parse_json(Entities)[8].Upn), parse_json(Entities)[8].Upn,
parse_json(Entities)[9].Upn)
| where Entities has_any (EmailAddresses)
| extend timestamp = TimeGenerated, AccountCustomEntity = tostring(UPN)),
(AzureDiagnostics
| where ResourceType =~ "AZUREFIREWALLS"
| where msg_s has_any (DomainNames)
| extend timestamp = TimeGenerated))
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl", "InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_strontium_group_domains_july_2019" {
  name                       = "sdr_known_strontium_group_domains_july_2019"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known STRONTIUM group domains - July 2019"
  description                = "Matches domain name IOCs related to Strontium group activity published July 2019 with CommonSecurityLog, DnsEvents and VMConnection dataTypes. References: https://blogs.microsoft.com/on-the-issues/2019/07/17/new-cyberthreats-require-new-ways-to-protect-democracy/."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = dynamic(["irf.services","microsoft-onthehub.com","msofficelab.com","com-mailbox.com","my-sharefile.com","my-sharepoints.com",
"accounts-web-mail.com","customer-certificate.com","session-users-activities.com","user-profile-credentials.com","verify-linke.com","support-servics.net",
"onedrive-sharedfile.com","onedrv-live.com","transparencyinternational-my-sharepoint.com","transparencyinternational-my-sharepoints.com","soros-my-sharepoint.com"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| extend Account = SourceUserID, Host = DeviceName, IPAddress = SourceIP),
(DnsEvents
| extend IPAddress = ClientIP, DNSName = Name, Host = Computer),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| extend IPAddress = RemoteIp, Host = Computer),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| extend DNSName = Request_Name
| extend IPAddress = ClientIP),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost)
)
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend timestamp = TimeGenerated, IPCustomEntity = IPAddress, AccountCustomEntity = Account, HostCustomEntity = Host
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_known_zinc_comebacker_and_klackring_malware_hashes" {
  name                       = "sdr_known_zinc_comebacker_and_klackring_malware_hashes"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Known ZINC Comebacker and Klackring malware hashes"
  description                = "ZINC attacks against security researcher campaign malware hashes."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let tokens = dynamic(["SSL_HandShaking", "ASN2_TYPE_new", "sql_blob_open", "cmsSetLogHandlerTHR", "ntSystemInfo", "SetWebFilterString", "CleanupBrokerString", "glInitSampler", "deflateSuffix", "ntWindowsProc"]);
let DomainNames = dynamic(['codevexillium.org', 'angeldonationblog.com', 'investbooking.de', 'krakenfolio.com']);
let SHA256Hash = dynamic(['58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495','e0e59bfc22876c170af65dcbf19f744ae560cc43b720b23b9d248f4505c02f3e','3d3195697521973efe0097a320cbce0f0f98d29d50e044f4505e1fbc043e8cf9', '0a2d81164d524be7022ba8fd4e1e8e01bfd65407148569d172e2171b5cd76cd4', '96d7a93f6691303d39a9cc270b8814151dfec5683e12094537fd580afdf2e5fe','dc4cf164635db06b2a0b62d313dbd186350bca6fc88438617411a68df13ec83c', '46efd5179e43c9cbf07dcec22ce0d5527e2402655aee3afc016e5c260650284a', '95e42a94d4df1e7e472998f43b9879eb34aaa93f3705d7d3ef9e3b97349d7008', '9d5320e883264a80ea214077f44b1d4b22155446ad5083f4b27d2ab5bd127ef5', '9fd05063ad203581a126232ac68027ca731290d17bd43b5d3311e8153c893fe3', 'ada7e80c9d09f3efb39b729af238fcdf375383caaf0e9e0aed303931dc73b720', 'edb1597789c7ed784b85367a36440bf05267ac786efe5a4044ec23e490864cee', '33665ce1157ddb7cd7e905e3356b39245dfba17b7a658bdbf02b6968656b9998', '3ab770458577eb72bd6239fe97c35e7eb8816bce5a4b47da7bd0382622854f7c', 'b630ad8ffa11003693ce8431d2f1c6b8b126cd32b657a4bfa9c0dbe70b007d6c', '53f3e55c1217dafb8801af7087e7d68b605e2b6dde6368fceea14496c8a9f3e5', '99c95b5272c5b11093eed3ef2272e304b7a9311a22ff78caeb91632211fcb777', 'f21abadef52b4dbd01ad330efb28ef50f8205f57916a26daf5de02249c0f24ef', '2cbdea62e26d06080d114bbd922d6368807d7c6b950b1421d0aa030eca7e85da', '079659fac6bd9a1ce28384e7e3a465be4380acade3b4a4a4f0e67fd0260e9447']);
let SigNames = dynamic(["Backdoor:Script/ComebackerCompile.A!dha", "Trojan:Win64/Comebacker.A!dha", "Trojan:Win64/Comebacker.A.gen!dha", "Trojan:Win64/Comebacker.B.gen!dha", "Trojan:Win32/Comebacker.C.gen!dha", "Trojan:Win32/Klackring.A!dha", "Trojan:Win32/Klackring.B!dha"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where isnotempty(FileHash)
| where FileHash in~ (SHA256Hash) or DNSName in~ (DomainNames)
| extend Account = SourceUserID, Computer = DeviceName, IPAddress = SourceIP
| project Type, TimeGenerated, Computer, Account, IPAddress, FileHash, DNSName
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend DataType = "DnsEvents", IPAddress = ClientIP
| project Type, TimeGenerated, Computer, IPAddress, DNSName
),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = RemoteIp
| project Type, TimeGenerated, Computer, IPAddress, DNSName
),
(Event
//This query uses sysmon data depending on table name used this may need updataing
| where Source == "Microsoft-Windows-Sysmon"
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Hashes = EventDetail.[16].["#text"]
| where isnotempty(Hashes)
| parse Hashes with * 'SHA256=' SHA256 ',' *
| where SHA256 in~ (SHA256Hash)
| extend Type = strcat(Type, ": ", Source), Account = UserName, FileHash = Hashes
| project Type, TimeGenerated, Computer, Account, FileHash
),
(DeviceFileEvents
| where SHA256 in~ (SHA256Hash)
| extend Account = RequestAccountName, Computer = DeviceName, IPAddress = RequestSourceIP, CommandLine = InitiatingProcessCommandLine, FileHash = SHA256
| project Type, TimeGenerated, Computer, Account, IPAddress, CommandLine, FileHash
),
(DeviceNetworkEvents
| where RemoteUrl in~ (DomainNames)
| extend Computer = DeviceName, IPAddress = LocalIP, Account = InitiatingProcessAccountName
| project Type, TimeGenerated, Computer, Account, IPAddress, RemoteUrl
),
(SecurityAlert
| where Entities has_any (SigNames)
| extend Computer = tostring(parse_json(Entities)[0].HostName)
| project Type, TimeGenerated, Computer
),
(DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "rundll32.exe"
| where (ProcessCommandLine has "is64bitoperatingsystem" and ProcessCommandLine has "Debug\\Browse") or (ProcessCommandLine has_any (tokens))
| extend Computer = DeviceName, Account = AccountName, CommandLine = ProcessCommandLine
| project Type, TimeGenerated, Computer, Account, CommandLine, FileName
),
(SecurityEvent
| where ProcessName has_any ("powershell.exe", "rundll32.exe")
| where (CommandLine has "is64bitoperatingsystem" and CommandLine has "Debug\\Browse") or (CommandLine has_any (tokens))
| project Type, TimeGenerated, Computer, Account, ProcessName, CommandLine
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPAddress = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Execution"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_mfa_disabled_for_a_user" {
  name                       = "sdr_mfa_disabled_for_a_user"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "MFA disabled for a user"
  description                = "Multi-Factor Authentication (MFA) helps prevent credential compromise. This alert identifies when an attempt has been made to diable MFA for a user"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
(union isfuzzy=true
(AuditLogs
| where OperationName =~ "Disable Strong Authentication"
| extend IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)),
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend Targetprop = todynamic(TargetResources)
| extend TargetUser = tostring(Targetprop[0].userPrincipalName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, InitiatedByUser , Operation = OperationName , CorrelationId, IPAddress, Category, Source = SourceSystem , AADTenantId, Type
),
(AWSCloudTrail
| where EventName in~ ("DeactivateMFADevice", "DeleteVirtualMFADevice")
| extend InstanceProfileName = tostring(parse_json(RequestParameters).InstanceProfileName)
| extend TargetUser = tostring(parse_json(RequestParameters).userName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, Source = EventSource , Operation = EventName , TenantorInstance_Detail = InstanceProfileName, IPAddress = SourceIpAddress
)
)
| extend timestamp = StartTimeUtc, AccountCustomEntity = User, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_modified_domain_federation_trust_settings" {
  name                       = "sdr_modified_domain_federation_trust_settings"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Modified domain federation trust settings"
  description                = "This will alert when a user or application modifies the federation settings on the domain or Update domain authentication from Managed to Federated. For example, this alert will trigger when a new Active Directory Federated Service (ADFS) TrustedRealm object, such as a signing certificate, is added to the domain. Modification to domain federation settings should be rare. Confirm the added or modified target domain/URL is legitimate administrator behavior. To understand why an authorized user may update settings for a federated domain in Office 365, Azure, or Intune, see: https://docs.microsoft.com/office365/troubleshoot/active-directory/update-federated-domain-office-365. For details on security realms that accept security tokens, see the ADFS Proxy Protocol (MS-ADFSPP) specification: https://docs.microsoft.com/openspecs/windows_protocols/ms-adfspp/e7b9ea73-1980-4318-96a6-da559486664b. For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
(union isfuzzy=true
(
AuditLogs
| where OperationName =~ "Set federation settings on domain"
//| where Result =~ "success" // commenting out, as it may be interesting to capture failed attempts
| mv-expand TargetResources
| extend modifiedProperties = parse_json(TargetResources).modifiedProperties
| mv-expand modifiedProperties
| extend targetDisplayName = tostring(parse_json(modifiedProperties).displayName)
| mv-expand AdditionalDetails
),
(
AuditLogs
| where OperationName =~ "Set domain authentication"
//| where Result =~ "success" // commenting out, as it may be interesting to capture failed attempts
| mv-expand TargetResources
| extend modifiedProperties = parse_json(TargetResources).modifiedProperties
| mv-expand modifiedProperties
| extend targetDisplayName = tostring(parse_json(modifiedProperties).displayName), NewDomainValue=tostring(parse_json(modifiedProperties).newValue)
| where NewDomainValue has "Federated"
)
)
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, AADOperationType, targetDisplayName, Result, InitiatingIpAddress, UserAgent, CorrelationId, TenantId, AADTenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response, Incident grouping(DNS)
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_solorigate_network_beacon" {
  name                       = "sdr_solorigate_network_beacon"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Solorigate Network Beacon"
  description                = "Identifies a match across various data feeds for domains IOCs related to the Solorigate incident. References: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/, https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html?1"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let domains = dynamic(["incomeupdate.com", "zupertech.com", "databasegalore.com", "panhardware.com", "avsvmcloud.com", "digitalcollege.org", "freescanonline.com", "deftsecurity.com", "thedoccloud.com", "virtualdataserver.com", "lcomputers.com", "webcodez.com", "globalnetworkissues.com", "kubecloud.com", "seobundlekit.com", "solartrackingsystem.net", "virtualwebdata.com"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where DNSName in~ (domains) or DestinationHostName has_any (domains) or RequestURL has_any(domains)
| extend AccountCustomEntity = SourceUserID, HostCustomEntity = DeviceName, IPCustomEntity = SourceIP
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName in~ (domains)
| extend IPCustomEntity = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (domains)
| extend DNSName = Request_Name
| extend IPCustomEntity = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (domains)
| extend DNSName = DestinationHost
| extend IPCustomEntity = SourceHost
)
)
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Host"] # DNS not available
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response, Incident grouping(AzureResource)
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_application_consent_similar_to_o365_attack_toolkit" {
  name                       = "sdr_suspicious_application_consent_similar_to_o365_attack_toolkit"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious application consent similar to O365 Attack Toolkit"
  description                = "This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit). The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all. Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome! For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess", "DefenseEvasion"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_thallium_domains_included_in_dcu_takedown" {
  name                       = "sdr_thallium_domains_included_in_dcu_takedown"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "THALLIUM domains included in DCU takedown"
  description                = "THALLIUM spearphishing and command and control domains included in December 2019 DCU/MSTIC takedown. Matches domain name IOCs related to the THALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes. References: https://blogs.microsoft.com/on-the-issues/2019/12/30/microsoft-court-action-against-nation-state-cybercrime/"
  enabled                    = true
  severity                   = "High"
  query                      = <<QUERY
let DomainNames = dynamic(["seoulhobi.biz", "reader.cash", "pieceview.club", "app-wallet.com", "bigwnet.com", "bitwoll.com", "cexrout.com", "change-pw.com", "checkprofie.com", "cloudwebappservice.com", "ctquast.com", "dataviewering.com", "day-post.com", "dialy-post.com", "documentviewingcom.com", "dovvn-mail.com", "down-error.com", "drivecheckingcom.com", "drog-service.com", "encodingmail.com", "filinvestment.com", "foldershareing.com", "golangapis.com", "hotrnall.com", "lh-logins.com", "login-use.com", "mail-down.com", "matmiho.com", "mihomat.com", "natwpersonal-online.com", "nidlogin.com", "nid-login.com", "nidlogon.com", "pw-change.com", "rnaii.com", "rnailm.com", "sec-live.com", "secrityprocessing.com", "securitedmode.com", "securytingmail.com", "set-login.com", "usrchecking.com", "com-serviceround.info", "mai1.info", "reviewer.mobi", "files-download.net", "fixcool.net", "hanrnaii.net", "office356-us.org", "smtper.org"]);
(union isfuzzy=true
(CommonSecurityLog
| parse Message with * '(' DNSName ')' *
| where isnotempty(FileHash)
| where DNSName in~ (DomainNames)
| extend Account = SourceUserID, Computer = DeviceName, IPAddress = SourceIP
),
(DnsEvents
| extend DNSName = Name
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = ClientIP
),
(VMConnection
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| where isnotempty(DNSName)
| where DNSName in~ (DomainNames)
| extend IPAddress = RemoteIp
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend DNSName = Request_Name
| extend IPAddress = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend DNSName = DestinationHost
| extend IPAddress = SourceHost
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Scheduled - Medium
# TBM - Set logic rule(custom details), Automated response, Incident grouping(AzureResource)
/* resource "azurerm_sentinel_alert_rule_scheduled" "sdr_wso2_nmap_detected_in_aks" {
  name                       = "sdr_wso2_nmap_detected_in_aks"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "[WSO2] NMAP detected in AKS"
  description                = "This is a custom rule where if any attacker runs NMAP script in an AKS Pod"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
AzureDiagnostics
| where Category == "kube-audit"
| where log_s contains "Nmap Scripting Engine"
| where parse_json(tostring(parse_json(log_s).responseStatus)).code == 200
| project TimeGenerated, parse_json(log_s).stageTimestamp, parse_json(log_s).userAgent, parse_json(tostring(parse_json(log_s).sourceIPs))[0], parse_json(log_s).requestURI, ccpNamespace_s, log_s, _ResourceId
QUERY
  query_frequency            = "PT12H"
  query_period               = "PT12H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Execution", "Discovery", "CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"] # AzureResource not available
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
} */

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_anomalous_sign_in_location_by_user_account_and_authenticating_application" {
  name                       = "sdr_anomalous_sign_in_location_by_user_account_and_authenticating_application"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Anomalous sign-in location by user account and authenticating application"
  description                = "This query over Azure Active Directory sign-in considers all user sign-ins for each Azure Active Directory application and picks out the most anomalous change in location profile for a user within an individual application. An alert is generated for recent sign-ins that have location counts that are anomalous over last day but also over the last 3-day and 7-day periods. Please note that on workspaces with larger volume of Signin data (~10M+ events a day) may timeout when using this default query time period. It is recommended that you test and tune this appropriately for the workspace."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let lookBack_long = 7d;
let lookBack_med = 3d;
let lookBack = 1d;
let aadFunc = (tableName:string){
table(tableName)
| where TimeGenerated >= startofday(ago(lookBack_long))
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend locationString = strcat(tostring(LocationDetails.countryOrRegion), "/", tostring(LocationDetails.state), "/", tostring(LocationDetails.city), ";")
| project TimeGenerated, AppDisplayName , UserPrincipalName, locationString
// Create time series
| make-series dLocationCount = dcount(locationString) on TimeGenerated in range(startofday(ago(lookBack_long)),now(), 1d)
by UserPrincipalName, AppDisplayName
// Compute best fit line for each entry
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dLocationCount)
// Chart the 3 most interesting lines
// A 0-value slope corresponds to an account being completely stable over time for a given Azure Active Directory application
| where Slope > 0.3
| top 50 by Slope desc
| join kind = leftsemi (
table(tableName)
| where TimeGenerated >= startofday(ago(lookBack_med))
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend locationString = strcat(tostring(LocationDetails.countryOrRegion), "/", tostring(LocationDetails.state), "/", tostring(LocationDetails.city), ";")
| project TimeGenerated, AppDisplayName , UserPrincipalName, locationString
| make-series dLocationCount = dcount(locationString) on TimeGenerated in range(startofday(ago(lookBack_med)) ,now(), 1d)
by UserPrincipalName, AppDisplayName
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dLocationCount)
| where Slope > 0.3
| top 50 by Slope desc
) on UserPrincipalName, AppDisplayName
| join kind = leftsemi (
table(tableName)
| where TimeGenerated >= startofday(ago(lookBack))
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend locationString = strcat(tostring(LocationDetails.countryOrRegion), "/", tostring(LocationDetails.state), "/", tostring(LocationDetails.city), ";")
| project TimeGenerated, AppDisplayName , UserPrincipalName, locationString
| make-series dLocationCount = dcount(locationString) on TimeGenerated in range(startofday(ago(lookBack)) ,now(), 1d)
by UserPrincipalName, AppDisplayName
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dLocationCount)
| where Slope > 5
| top 50 by Slope desc
// Higher threshold requirement on last day anomaly
) on UserPrincipalName, AppDisplayName
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_attempts_to_sign_in_to_disabled_accounts" {
  name                       = "sdr_attempts_to_sign_in_to_disabled_accounts"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Attempts to sign in to disabled accounts"
  description                = "Identifies failed attempts to sign in to disabled accounts across multiple Azure Applications. Default threshold for Azure Applications attempted to sign in to is 3. References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes 50057 - User account is disabled. The account has been disabled by an administrator."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let threshold = 3;
let aadFunc = (tableName:string){
table(tableName)
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), applicationCount = dcount(AppDisplayName),
applicationSet = make_set(AppDisplayName), count() by UserPrincipalName, IPAddress, Type
| where applicationCount >= threshold
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_aad_powershell_accessing_non_aad_resources" {
  name                       = "sdr_aad_powershell_accessing_non_aad_resources"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Azure Active Directory PowerShell accessing non-AAD resources"
  description                = "This will alert when a user or application signs in using Azure Active Directory PowerShell to access non-Active Directory resources, such as the Azure Key Vault, which may be undesired or unauthorized behavior. For capabilities and expected behavior of the Azure Active Directory PowerShell module, see: https://docs.microsoft.com/powershell/module/azuread/?view=azureadps-2.0. For further information on Azure Active Directory Signin activity reports, see: https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let aadFunc = (tableName:string){
table(tableName)
| where AppId =~ "1b730954-1685-4b74-9bfd-dac224a7b894" // AppDisplayName IS Azure Active Directory PowerShell
| where TokenIssuerType =~ "AzureAD"
| where ResourceIdentity !in ("00000002-0000-0000-c000-000000000000", "00000003-0000-0000-c000-000000000000") // ResourceDisplayName IS NOT Windows Azure Active Directory OR Microsoft Graph
| extend Status = todynamic(Status)
| where Status.errorCode == 0 // Success
| project-reorder IPAddress, UserAgent, ResourceDisplayName, UserDisplayName, UserId, UserPrincipalName, Type
| order by TimeGenerated desc
// New entity mapping
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_credential_added_after_admin_consented_to_application" {
  name                       = "sdr_credential_added_after_admin_consented_to_application"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Credential added after admin consented to Application"
  description                = "This query will identify instances where Service Principal credentials were added to an application by one user after the application was granted admin consent rights by another user. If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential. Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow. For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let auditLookbackStart = 2d;
let auditLookbackEnd = 1d;
AuditLogs
| where TimeGenerated >= ago(auditLookbackStart)
| where OperationName =~ "Consent to application"
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetResourceType = tostring(target.type)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend isAdminConsent = targetModifiedProp[0].newValue
| extend Consent_ServicePrincipalNames = targetModifiedProp[5].newValue
| extend Consent_Permissions = targetModifiedProp[4].newValue
| extend Consent_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Consent_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| join (
AuditLogs
| where TimeGenerated >= ago(auditLookbackEnd)
| where OperationName =~ "Add service principal credentials"
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend Credential_KeyDescription = targetModifiedProp[0].newValue
| extend UpdatedProperties = targetModifiedProp[1].newValue
| extend Credential_ServicePrincipalNames = targetModifiedProp[2].newValue
| extend Credential_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Credential_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
) on targetResourceName, targetResourceID
| extend TimeConsent = TimeGenerated, TimeCred = TimeGenerated1
| where TimeConsent > TimeCred
| project TimeConsent, TimeCred, Consent_InitiatingUserOrApp, Credential_InitiatingUserOrApp, targetResourceName, targetResourceType, isAdminConsent, Consent_ServicePrincipalNames, Credential_ServicePrincipalNames, Consent_Permissions, Credential_KeyDescription, Consent_InitiatingIpAddress, Credential_InitiatingIpAddress
| extend timestamp = TimeConsent, AccountCustomEntity = Consent_InitiatingUserOrApp, IPCustomEntity = Consent_InitiatingIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P2D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_distributed_password_cracking_attempts_in_azuread" {
  name                       = "sdr_distributed_password_cracking_attempts_in_azuread"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Distributed Password cracking attempts in AzureAD"
  description                = "Identifies distributed password cracking attempts from the Azure Active Directory SigninLogs. The query looks for unusually high number of failed password attempts coming from multiple locations for a user account. References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes 50053 Account is locked because the user tried to sign in too many times with an incorrect user ID or password. 50055 Invalid password, entered expired password. 50056 Invalid or null password - Password does not exist in store for this user. 50126 Invalid username or password, or invalid on-premises username or password."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let s_threshold = 30;
let l_threshold = 3;
let aadFunc = (tableName:string){
table(tableName)
| where OperationName =~ "Sign-in activity"
// Error codes that we want to look at as they are related to the use of incorrect password.
| where ResultType in ("50126", "50053" , "50055", "50056")
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend LocationString = strcat(tostring(LocationDetails.countryOrRegion), "/", tostring(LocationDetails.state), "/", tostring(LocationDetails.city))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), LocationCount=dcount(LocationString), Location = make_set(LocationString),
IPAddress = make_set(IPAddress), IPAddressCount = dcount(IPAddress), AppDisplayName = make_set(AppDisplayName), ResultDescription = make_set(ResultDescription),
Browser = make_set(Browser), OS = make_set(OS), SigninCount = count() by UserPrincipalName, Type
// Setting a generic threshold - Can be different for different environment
| where SigninCount > s_threshold and LocationCount >= l_threshold
| extend tostring(Location), tostring(IPAddress), tostring(AppDisplayName), tostring(ResultDescription), tostring(Browser), tostring(OS)
| distinct *
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT8H"
  query_period               = "PT8H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_failed_azuread_logons_but_success_logon_to_host" {
  name                       = "sdr_failed_azuread_logons_but_success_logon_to_host"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Failed AzureAD logons but success logon to host"
  description                = "Identifies a list of IP addresses with a minimum number (default of 5) of failed logon attempts to Azure Active Directory. Uses that list to identify any successful remote logons to hosts from these IPs within the same timeframe."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
//Adjust this threshold to fit environment
let signin_threshold = 5;
//Make a list of all IPs with failed signins to AAD above our threshold
let aadFunc = (tableName:string){
let suspicious_signins =
table(tableName)
| where ResultType !in ("0", "50125", "50140")
| where IPAddress !in ('127.0.0.1', '::1')
| summarize count() by IPAddress
| where count_ > signin_threshold
| summarize make_set(IPAddress);
//See if any of these IPs have sucessfully logged into *nix hosts
let linux_logons =
Syslog
| where Facility contains "auth" and ProcessName != "sudo"
| where SyslogMessage has "Accepted"
| extend SourceIP = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage)
| where SourceIP in (suspicious_signins)
| extend Reason = "Multiple failed AAD logins from IP address"
| project TimeGenerated, Computer, HostIP, IpAddress = SourceIP, SyslogMessage, Facility, ProcessName, Reason;
//See if any of these IPs have sucessfully logged into Windows hosts
let win_logons =
SecurityEvent
| where EventID == 4624
| where LogonType in (10, 7, 3)
| where IpAddress != "-"
| where IpAddress in (suspicious_signins)
| extend Reason = "Multiple failed AAD logins from IP address"
| project TimeGenerated, Account, AccountType, Computer, Activity, EventID, LogonProcessName, IpAddress, LogonTypeName, TargetUserSid, Reason;
union isfuzzy=true linux_logons,win_logons
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, IPCustomEntity = IpAddress, HostCustomEntity = Computer
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_failed_host_logons_but_success_logon_to_azuread" {
  name                       = "sdr_failed_host_logons_but_success_logon_to_azuread"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Failed host logons but success logon to AzureAD"
  description                = "Identifies a list of IP addresses with a minimum number(default of 5) of failed logon attempts to remote hosts. Uses that list to identify any successful logons to Azure Active Directory from these IPs within the same timeframe."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
//Adjust this threshold to fit environment
let signin_threshold = 5;
//Make a list of IPs with failed Windows host logins above threshold
let win_fails =
SecurityEvent
| where EventID == 4625
| where LogonType in (10, 7, 3)
| where IpAddress != "-"
| summarize count() by IpAddress
| where count_ > signin_threshold
| summarize make_list(IpAddress);
//Make a list of IPs with failed *nix host logins above threshold
let nix_fails =
Syslog
| where Facility contains 'auth' and ProcessName != 'sudo'
| extend SourceIP = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage)
| where SourceIP != "" and SourceIP != "127.0.0.1"
| summarize count() by SourceIP
| where count_ > signin_threshold
| summarize make_list(SourceIP);
//See if any of the IPs with failed host logins hve had a sucessful Azure AD login
let aadFunc = (tableName:string){
table(tableName)
| where ResultType !in ("0", "50125", "50140")
| where IPAddress in (win_fails) or IPAddress in (nix_fails)
| extend Reason= "Multiple failed host logins from IP address with successful Azure AD login"
| extend timstamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, Type = Type
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_mail_read_permissions_granted_to_application" {
  name                       = "sdr_mail_read_permissions_granted_to_application"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Mail.Read Permissions Granted to Application"
  description                = "This query look for applications that have been granted (Delegated or App/Role) permissions to Read Mail (Permissions field has Mail.Read) and subsequently has been consented to. This can help identify applications that have been abused to gain access to mailboxes."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
AuditLogs
| where Category =~ "ApplicationManagement"
| where ActivityDisplayName has_any ("Add delegated permission grant","Add app role assignment to service principal")
| where Result =~ "success"
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend props = parse_json(tostring(TargetResources[0].modifiedProperties))
| mv-expand props
| extend UserAgent = tostring(AdditionalDetails[0].value)
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend UserIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend DisplayName = tostring(props.displayName)
| extend Permissions = tostring(parse_json(tostring(props.newValue)))
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
| extend PermissionsAddedTo = tostring(TargetResources[0].displayName)
| extend Type = tostring(TargetResources[0].type)
| project-away props
| join kind=leftouter(
AuditLogs
| where ActivityDisplayName has "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| project AppName, AppId, CorrelationId) on CorrelationId
| project-reorder TimeGenerated, OperationName, InitiatingUser, UserIPAddress, UserAgent, PermissionsAddedTo, Permissions, AppName, AppId, CorrelationId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUser, IPCustomEntity = UserIPAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Persistence"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_malformed_user_agent" {
  name                       = "sdr_malformed_user_agent"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Malformed user agent"
  description                = "Malware authors will sometimes hardcode user agent string values when writing the network communication component of their malware. Malformed user agents can be an indication of such malware."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
(union isfuzzy=true
(OfficeActivity | where UserAgent != ""),
(OfficeActivity
| where RecordType in ("AzureActiveDirectory", "AzureActiveDirectoryStsLogon")
| extend OperationName = Operation
| parse ExtendedProperties with * 'User-Agent\\":\\"' UserAgent2 '\\' *
| parse ExtendedProperties with * 'UserAgent", "Value": "' UserAgent1 '"' *
| where isnotempty(UserAgent1) or isnotempty(UserAgent2)
| extend UserAgent = iff( RecordType == 'AzureActiveDirectoryStsLogon', UserAgent1, UserAgent2)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = ClientIP, Account = UserId, Type, RecordType, Operation
),
(AzureDiagnostics
| where ResourceType =~ "APPLICATIONGATEWAYS"
| where OperationName =~ "ApplicationGatewayAccess"
| extend ClientIP = columnifexists("clientIP_s", "None"), UserAgent = columnifexists("userAgent_s", "None")
| where UserAgent != '-'
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = ClientIP, requestUri_s, httpMethod_s, host_s, requestQuery_s, Type
),
(
W3CIISLog
| where isnotempty(csUserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent = csUserAgent, SourceIP = cIP, Account = csUserName, Type, sSiteName, csMethod, csUriStem
),
(
AWSCloudTrail
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = SourceIpAddress, Account = UserIdentityUserName, Type, EventSource, EventName
),
(SigninLogs
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = IPAddress, Account = UserPrincipalName, Type, OperationName, tostring(LocationDetails), tostring(DeviceDetail), AppDisplayName, ClientAppUsed
),
(AADNonInteractiveUserSignInLogs
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = IPAddress, Account = UserPrincipalName, Type, OperationName, tostring(LocationDetails), tostring(DeviceDetail), AppDisplayName, ClientAppUsed
)
)
// Likely artefact of hardcoding
| where UserAgent startswith "User" or UserAgent startswith '\"'
// Incorrect casing
or (UserAgent startswith "Mozilla" and not(UserAgent containscs "Mozilla"))
// Incorrect casing
or UserAgent containscs "(Compatible;"
// Missing MSIE version
or UserAgent matches regex @"MSIE\s?;"
// Incorrect spacing around MSIE version
or UserAgent matches regex @"MSIE(?:\d|.{1,5}?\d\s;)"
| extend timestamp = StartTime, IPCustomEntity = SourceIP, AccountCustomEntity = Account
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess", "CommandAndControl", "Execution"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_new_access_credential_added_to_application_or_service_principal" {
  name                       = "sdr_new_access_credential_added_to_application_or_service_principal"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "New access credential added to Application or Service Principal"
  description                = "This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where a verify KeyCredential was already present for the app. If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential. Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
| where Result =~ "success"
| mv-expand target = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set != "[]"
| extend diff = set_difference(new_value_set, old_value_set)
| where isnotempty(diff)
| parse diff with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify" or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Azure Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away diff, new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response, Incident grouping(DNS)
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_nobelium_domain_and_ip_iocs_march_2021" {
  name                       = "sdr_nobelium_domain_and_ip_iocs_march_2021"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "NOBELIUM - Domain and IP IOCs - March 2021"
  description                = "Identifies a match across various data feeds for domains and IP IOCs related to NOBELIUM. References: https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let DomainNames = dynamic(['onetechcompany.com', 'reyweb.com', 'srfnetwork.org', 'sense4baby.fr', 'nikeoutletinc.org', 'megatoolkit.com']);
let IPList = dynamic(['185.225.69.69']);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
(union isfuzzy=true
(CommonSecurityLog
| where SourceIP in (IPList) or DestinationIP in (IPList) or DestinationHostName in~ (DomainNames) or RequestURL has_any (DomainNames) or Message has_any (IPList)
| parse Message with * '(' DNSName ')' *
| extend MessageIP = extract(IPRegex, 0, Message)
| extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", MessageIP in (IPList), "Message", RequestURL in (DomainNames), "RequestUrl", "NoMatch")
| extend timestamp = TimeGenerated, IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "NoMatch"), AccountCustomEntity = SourceUserID
),
(DnsEvents
| where IPAddresses in (IPList) or Name in~ (DomainNames)
| extend DestinationIPAddress = IPAddresses, DNSName = Name, Host = Computer
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
),
(VMConnection
| where SourceIp in (IPList) or DestinationIp in (IPList) or RemoteDnsCanonicalNames has_any (DomainNames)
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| extend IPMatch = case( SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated, IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "NoMatch"), HostCustomEntity = Computer
),
(OfficeActivity
| where ClientIP in (IPList)
| extend timestamp = TimeGenerated, IPCustomEntity = ClientIP, AccountCustomEntity = UserId
),
(DeviceNetworkEvents
| where RemoteUrl has_any (DomainNames) or RemoteIP in (IPList)
| extend timestamp = TimeGenerated, DNSName = RemoteUrl, IPCustomEntity = RemoteIP, HostCustomEntity = DeviceName
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (DomainNames)
| extend timestamp = TimeGenerated, DNSName = Request_Name, IPCustomEntity = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (DomainNames)
| extend timestamp = TimeGenerated, DNSName = DestinationHost, IPCustomEntity = SourceHost
)
)
QUERY
  query_frequency            = "PT6H"
  query_period               = "PT6H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host", "Ip"] # DNS not available
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_password_spray_attack_against_azure_ad_application" {
  name                       = "sdr_password_spray_attack_against_azure_ad_application"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Password spray attack against Azure AD application"
  description                = "Identifies evidence of password spray activity against Azure AD applications by looking for failures from multiple accounts from the same IP address within a time window. If the number of accounts breaches the threshold just once, all failures from the IP address within the time range are bought into the result. Details on whether there were successful authentications by the IP address within the time window are also included. This can be an indicator that an attack was successful. The default failure acccount threshold is 5, Default time window for failures is 20m and default look back window is 3 days Note: Due to the number of possible accounts involved in a password spray it is not possible to map identities to a custom entity. References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let timeRange = 3d;
let lookBack = 7d;
let authenticationWindow = 20m;
let authenticationThreshold = 5;
let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}";
let failureCodes = dynamic([50053, 50126, 50055]); // invalid password, account is locked - too many sign ins, expired password
let successCodes = dynamic([0, 50055, 50057, 50155, 50105, 50133, 50005, 50076, 50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129]);
// Lookup up resolved identities from last 7 days
let aadFunc = (tableName:string){
let identityLookup = table(tableName)
| where TimeGenerated >= ago(lookBack)
| where not(Identity matches regex isGUID)
| where isnotempty(UserId)
| summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName, Type;
// collect window threshold breaches
table(tableName)
| where TimeGenerated > ago(timeRange)
| where ResultType in(failureCodes)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), make_set(ClientAppUsed), count() by bin(TimeGenerated, authenticationWindow), IPAddress, AppDisplayName, UserPrincipalName, Type
| summarize FailedPrincipalCount = dcount(UserPrincipalName) by bin(TimeGenerated, authenticationWindow), IPAddress, AppDisplayName, Type
| where FailedPrincipalCount >= authenticationThreshold
| summarize WindowThresholdBreaches = count() by IPAddress, Type
| join kind= inner (
// where we breached a threshold, join the details back on all failure data
table(tableName)
| where TimeGenerated > ago(timeRange)
| where ResultType in(failureCodes)
| extend LocationDetails = todynamic(LocationDetails)
| extend FullLocation = strcat(LocationDetails.countryOrRegion,'|', LocationDetails.state, '|', LocationDetails.city)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), make_set(ClientAppUsed), make_set(FullLocation), FailureCount = count() by IPAddress, AppDisplayName, UserPrincipalName, UserDisplayName, Identity, UserId, Type
// lookup any unresolved identities
| extend UnresolvedUserId = iff(Identity matches regex isGUID, UserId, "")
| join kind= leftouter (
identityLookup
) on $left.UnresolvedUserId==$right.UserId
| extend UserDisplayName=iff(isempty(lu_UserDisplayName), UserDisplayName, lu_UserDisplayName)
| extend UserPrincipalName=iff(isempty(lu_UserPrincipalName), UserPrincipalName, lu_UserPrincipalName)
| summarize StartTime = min(StartTime), EndTime = max(EndTime), make_set(UserPrincipalName), make_set(UserDisplayName), make_set(set_ClientAppUsed), make_set(set_FullLocation), make_list(FailureCount) by IPAddress, AppDisplayName, Type
| extend FailedPrincipalCount = arraylength(set_UserPrincipalName)
) on IPAddress
| project IPAddress, StartTime, EndTime, TargetedApplication=AppDisplayName, FailedPrincipalCount, UserPrincipalNames=set_UserPrincipalName, UserDisplayNames=set_UserDisplayName, ClientAppsUsed=set_set_ClientAppUsed, Locations=set_set_FullLocation, FailureCountByPrincipal=list_FailureCount, WindowThresholdBreaches, Type
| join kind= inner (
table(tableName) // get data on success vs. failure history for each IP
| where TimeGenerated > ago(timeRange)
| where ResultType in(successCodes) or ResultType in(failureCodes) // success or failure types
| summarize GlobalSuccessPrincipalCount = dcountif(UserPrincipalName, (ResultType in(successCodes))), ResultTypeSuccesses = make_set_if(ResultType, (ResultType in(successCodes))), GlobalFailPrincipalCount = dcountif(UserPrincipalName, (ResultType in(failureCodes))), ResultTypeFailures = make_set_if(ResultType, (ResultType in(failureCodes))) by IPAddress, Type
| where GlobalFailPrincipalCount > GlobalSuccessPrincipalCount // where the number of failed principals is greater than success - eliminates FPs from IPs who authenticate successfully alot and as a side effect have alot of failures
) on IPAddress
| project-away IPAddress1
| extend timestamp=StartTime, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P7D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_rare_application_consent" {
  name                       = "sdr_rare_application_consent"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Rare application consent"
  description                = "This will alert when the \"Consent to application\" operation occurs by a user that has not done this operation before or rarely does this. This could indicate that permissions to access the listed Azure App were provided to a malicious actor. Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)),
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)),
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType , CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P7D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 3
  suppression_enabled        = false
  tactics                    = ["Persistence", "LateralMovement", "Collection"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response, Query update
/* resource "azurerm_sentinel_alert_rule_scheduled" "sdr_several_deny_actions_registered" {
  name                       = "sdr_several_deny_actions_registered"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Several deny actions registered"
  description                = "Identifies attack pattern when attacker tries to move, or scan, from resource to resource on the network and creates an incident when a source has more than 1 registered deny action in Azure Firewall."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let threshold = 1;
AzureDiagnostics
| where OperationName in ("AzureFirewallApplicationRuleLog","AzureFirewallNetworkRuleLog")
| extend msg_s_replaced0 = replace(@"\s\s",@" ",msg_s)
| extend msg_s_replaced1 = replace(@"\.\s",@" ",msg_s_replaced0)
| extend msg_a = split(msg_s_replaced1," ")
| extend srcAddr_a = split(msg_a[3],":") , destAddr_a = split(msg_a[5],":")
| extend protocol = tostring(msg_a[0]), srcIp = tostring(srcAddr_a[0]), srcPort = tostring(srcAddr_a[1]), destIp = tostring(destAddr_a[0]), destPort = tostring(destAddr_a[1]), action = tostring(msg_a[7])
| where action == "Deny"
| extend url = iff(destIp matches regex "\\d+\\.\\d+\\.\\d+\\.\\d+","",destIp)
| summarize StartTime = min(TimeGenerated), count() by srcIp, destIp, url, action, protocol, ResourceId
| where count_ >= ["threshold"]
| extend timestamp = StartTime, URLCustomEntity = url, IPCustomEntity = srcIp
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 1
  suppression_enabled        = false
  tactics                    = ["Discovery", "LateralMovement", "CommandAndControl"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
} */

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_sign_ins_from_ips_that_attempt_sign_ins_to_disabled_accounts" {
  name                       = "sdr_sign_ins_from_ips_that_attempt_sign_ins_to_disabled_accounts"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Sign-ins from IPs that attempt sign-ins to disabled accounts"
  description                = "Identifies IPs with failed attempts to sign in to one or more disabled accounts signed in successfully to another account. References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes 50057 - User account is disabled. The account has been disabled by an administrator."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let aadFunc = (tableName:string){
table(tableName)
| where ResultType == "50057"
| where ResultDescription == "User account is disabled. The account has been disabled by an administrator."
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), disabledAccountLoginAttempts = count(),
disabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted = dcount(AppDisplayName), disabledAccountSet = makeset(UserPrincipalName),
applicationSet = makeset(AppDisplayName) by IPAddress, Type
| order by disabledAccountLoginAttempts desc
| join kind= leftouter (
// Consider these IPs suspicious - and alert any related successful sign-ins
SigninLogs
| where ResultType == 0
| summarize successfulAccountSigninCount = dcount(UserPrincipalName), successfulAccountSigninSet = makeset(UserPrincipalName, 15) by IPAddress, Type
// Assume IPs associated with sign-ins from 100+ distinct user accounts are safe
| where successfulAccountSigninCount < 100
) on IPAddress
// IPs from which attempts to authenticate as disabled user accounts originated, and had a non-zero success rate for some other account
| where successfulAccountSigninCount != 0
| project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts, disabledAccountsTargeted, disabledAccountSet, applicationSet,
successfulAccountSigninCount, successfulAccountSigninSet, Type
| order by disabledAccountLoginAttempts
| extend timestamp = StartTime, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Persistence", "InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_successful_logon_from_ip_and_failure_from_a_different_ip" {
  name                       = "sdr_successful_logon_from_ip_and_failure_from_a_different_ip"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Successful logon from IP and failure from a different IP"
  description                = "Identifies when a user account successfully logs onto an Azure App from one IP and within 10 mins failed to logon to the same App via a different IP. This may indicate a malicious attempt at password guessing based on knowledge of the users account."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let logonDiff = 10m;
let aadFunc = (tableName:string){
table(tableName)
| where ResultType == "0"
| where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online")
| project SuccessLogonTime = TimeGenerated, UserPrincipalName, SuccessIPAddress = IPAddress, AppDisplayName, SuccessIPBlock = strcat(split(IPAddress, ".")[0], ".", split(IPAddress, ".")[1]), Type
| join kind= inner (
table(tableName)
| where ResultType !in ("0", "50140")
| where ResultDescription !~ "Other"
| where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online")
| project FailedLogonTime = TimeGenerated, UserPrincipalName, FailedIPAddress = IPAddress, AppDisplayName, ResultType, ResultDescription, Type
) on UserPrincipalName, AppDisplayName
| where SuccessLogonTime < FailedLogonTime and FailedLogonTime - SuccessLogonTime <= logonDiff and FailedIPAddress !startswith SuccessIPBlock
| summarize FailedLogonTime = max(FailedLogonTime), SuccessLogonTime = max(SuccessLogonTime) by UserPrincipalName, SuccessIPAddress, AppDisplayName, FailedIPAddress, ResultType, ResultDescription, Type
| extend timestamp = SuccessLogonTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = SuccessIPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess", "InitialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_application_consent_similar_to_pwnauth" {
  name                       = "sdr_suspicious_application_consent_similar_to_pwnauth"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious application consent similar to PwnAuth"
  description                = "This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth). The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all. Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome! For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "offline"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess", "DefenseEvasion"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_granting_of_permissions_to_an_account" {
  name                       = "sdr_suspicious_granting_of_permissions_to_an_account"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious granting of permissions to an account"
  description                = "Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let starttime = 14d;
let endtime = 1d;
// The number of operations below which an IP address is considered an unusual source of role assignment operations
let alertOperationThreshold = 5;
let createRoleAssignmentActivity = AzureActivity
| where OperationName == "Create role assignment";
createRoleAssignmentActivity
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| summarize count() by CallerIpAddress, Caller
| where count_ >= alertOperationThreshold
| join kind = rightanti (
createRoleAssignmentActivity
| where TimeGenerated > ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatus = makelist(ActivityStatus),
OperationIds = makelist(OperationId), CorrelationId = makelist(CorrelationId), ActivityCountByCallerIPAddress = count()
by ResourceId, CallerIpAddress, Caller, OperationName, Resource, ResourceGroup
) on CallerIpAddress, Caller
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_number_of_resource_creation_or_deployment_activities" {
  name                       = "sdr_suspicious_number_of_resource_creation_or_deployment_activities"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious number of resource creation or deployment activities"
  description                = "The anomaly detection identifies activities that have occurred both since the start of the day 1 day ago and the start of the day 7 days ago. The start of the day is considered 12am UTC time."
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let szOperationNames = dynamic(["Create or Update Virtual Machine", "Create Deployment"]);
let starttime = 7d;
let endtime = 1d;
AzureActivity
| where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
| where OperationName in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatus = makelist(ActivityStatus),
OperationIds = makelist(OperationId), CallerIpAddress = makelist(CallerIpAddress), CorrelationId = makelist(CorrelationId)
by ResourceId, Caller, OperationName, Resource, ResourceGroup
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress)
| make-series dResourceCount=dcount(ResourceId)  default=0 on StartTimeUtc in range(startofday(ago(7d)), now(), 1d)
by Caller, tostring(ActivityTimeStamp), tostring(ActivityStatus), tostring(OperationIds), tostring(CallerIpAddress), tostring(CorrelationId), ResourceId, OperationName, Resource, ResourceGroup
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
| where Slope > 0.2
| join kind=leftsemi (
// Last day's activity is anomalous
AzureActivity
| where TimeGenerated >= startofday(ago(endtime))
| where OperationName in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatus = makelist(ActivityStatus),
OperationIds = makelist(OperationId), CallerIpAddress = makelist(CallerIpAddress), CorrelationId = makelist(CorrelationId)
by ResourceId, Caller, OperationName, Resource, ResourceGroup
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress)
| make-series dResourceCount=dcount(ResourceId)  default=0 on StartTimeUtc in range(startofday(ago(1d)), now(), 1d) 
by Caller, tostring(ActivityTimeStamp), tostring(ActivityStatus), tostring(OperationIds), tostring(CallerIpAddress), tostring(CorrelationId), ResourceId, OperationName, Resource, ResourceGroup
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
| where Slope > 0.2
) on Caller, CallerIpAddress
| mvexpand todynamic(ActivityTimeStamp), todynamic(ActivityStatus), todynamic(OperationIds), todynamic(CorrelationId)
| extend timestamp = ActivityTimeStamp, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P7D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_user_added_to_aad_privileged_groups" {
  name                       = "sdr_user_added_to_aad_privileged_groups"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "User added to Azure Active Directory Privileged Groups"
  description                = "This will alert when a user is added to any of the Privileged Groups. For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities. For Administrator role permissions in Azure Active Directory please see https://docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-admin-roles"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let timeframe = 1h;
let OperationList = dynamic(["Add member to role","Add member to role in PIM requested (permanent)"]);
let PrivilegedGroups = dynamic(["UserAccountAdmins","PrivilegedRoleAdmins","TenantAdmins"]);
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where LoggedByService =~ "Core Directory"
| where Category =~ "RoleManagement"
| where OperationName in~ (OperationList)
| mv-expand TargetResources
| extend modifiedProperties = parse_json(TargetResources).modifiedProperties
| mv-expand modifiedProperties
| extend DisplayName = tostring(parse_json(modifiedProperties).displayName), GroupName =  trim(@'"',tostring(parse_json(modifiedProperties).newValue))
| extend AppId = tostring(parse_json(parse_json(InitiatedBy).app).appId), InitiatedByDisplayName = tostring(parse_json(parse_json(InitiatedBy).app).displayName), ServicePrincipalId = tostring(parse_json(parse_json(InitiatedBy).app).servicePrincipalId), ServicePrincipalName = tostring(parse_json(parse_json(InitiatedBy).app).servicePrincipalName)
| where DisplayName =~ "Role.WellKnownObjectName"
| where GroupName in~ (PrivilegedGroups)
// If you want to still alert for operations from PIM, remove below filtering for MS-PIM.
| where InitiatedByDisplayName != "MS-PIM"
| project TimeGenerated, AADOperationType, Category, OperationName, AADTenantId, AppId, InitiatedByDisplayName, ServicePrincipalId, ServicePrincipalName, DisplayName, GroupName
| extend timestamp = TimeGenerated, AccountCustomEntity = ServicePrincipalName
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_ti_map_email_entity_to_azureactivity" {
  name                       = "sdr_ti_map_email_entity_to_azureactivity"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "(Preview) TI map Email entity to AzureActivity"
  description                = "Identifies a match in AzureActivity table from any Email IOC from TI"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
//Filtering the table for Email related IOCs
| where isnotempty(EmailSenderAddress)
| join (
    AzureActivity | where TimeGenerated >= ago(dt_lookBack) and isnotempty(Caller)
    | extend Caller = tolower(Caller)
    | where Caller matches regex emailregex
    | extend AzureActivity_TimeGenerated = TimeGenerated
)
on $left.EmailSenderAddress == $right.Caller
| where AzureActivity_TimeGenerated >= TimeGenerated and AzureActivity_TimeGenerated < ExpirationDateTime
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, Url, AzureActivity_TimeGenerated,
EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, Caller, Level, CallerIpAddress, Category, OperationName,
OperationNameValue, ActivityStatus, ResourceGroup, SubscriptionId
| extend timestamp = AzureActivity_TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress, URLCustomEntity = Url
QUERY
  query_frequency            = "PT1H"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_ti_map_email_entity_to_signinlogs" {
  name                       = "sdr_ti_map_email_entity_to_signinlogs"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "(Preview) TI map Email entity to SigninLogs"
  description                = "Identifies a match in SigninLogs table from any Email IOC from TI"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
let aadFunc = (tableName:string){
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
//Filtering the table for Email related IOCs
| where isnotempty(EmailSenderAddress)
| join (
    table(tableName) | where TimeGenerated >= ago(dt_lookBack) and isnotempty(UserPrincipalName)
    //Normalizing the column to lower case for exact match with EmailSenderAddress column
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where UserPrincipalName matches regex emailregex
    | extend Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
    | extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
    // renaming timestamp column so it is clear the log this came from SigninLogs table
    | extend SigninLogs_TimeGenerated = TimeGenerated, Type = Type
)
on $left.EmailSenderAddress == $right.UserPrincipalName
| where SigninLogs_TimeGenerated >= TimeGenerated and SigninLogs_TimeGenerated < ExpirationDateTime
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, SigninLogs_TimeGenerated,
EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, IPAddress, UserPrincipalName, AppDisplayName,
StatusCode, StatusDetails, NetworkIP, NetworkDestinationIP, NetworkSourceIP, Type
| extend timestamp = SigninLogs_TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, URLCustomEntity = Url
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT1H"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_ti_map_url_entity_to_azureactivity" {
  name                       = "sdr_ti_map_url_entity_to_azureactivity"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "(Preview) TI map URL entity to AzureActivity"
  description                = "Identifies a match in AzureActivity from any IP IOC from TI"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
// As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
// Taking the first non-empty value based on potential IOC match availability
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| join (
    AzureActivity | where TimeGenerated >= ago(dt_lookBack)
    // renaming time column so it is clear the log this came from
    | extend AzureActivity_TimeGenerated = TimeGenerated
)
on $left.TI_ipEntity == $right.CallerIpAddress
| where AzureActivity_TimeGenerated >= TimeGenerated and AzureActivity_TimeGenerated < ExpirationDateTime
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, AzureActivity_TimeGenerated,
TI_ipEntity, CallerIpAddress, Caller, OperationName, ActivityStatus, Category, ResourceId, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress
| extend timestamp = AzureActivity_TimeGenerated, IPCustomEntity = CallerIpAddress, AccountCustomEntity = Caller, URLCustomEntity = Url
QUERY
  query_frequency            = "PT1H"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_ti_map_url_entity_to_signinlogs" {
  name                       = "sdr_ti_map_url_entity_to_signinlogs"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "(Preview) TI map URL entity to SigninLogs"
  description                = "Identifies a match in SigninLogs from any IP IOC from TI"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let aadFunc = (tableName:string){
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
// As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
// Taking the first non-empty value based on potential IOC match availability
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| join (
    table(tableName) | where TimeGenerated >= ago(dt_lookBack)
    | extend Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
    | extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
    // renaming time column so it is clear the log this came from
    | extend SigninLogs_TimeGenerated = TimeGenerated, Type = Type
)
on $left.TI_ipEntity == $right.IPAddress
| where SigninLogs_TimeGenerated >= TimeGenerated and SigninLogs_TimeGenerated < ExpirationDateTime
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, SigninLogs_TimeGenerated,
TI_ipEntity, IPAddress, UserPrincipalName, AppDisplayName, StatusCode, StatusDetails, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
| extend timestamp = SigninLogs_TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, URLCustomEntity = Url
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "PT1H"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_ti_map_url_entity_to_auditlogs" {
  name                       = "sdr_ti_map_url_entity_to_auditlogs"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "(Preview) TI map URL entity to AuditLogs"
  description                = "Identifies a match in AuditLogs from any URL IOC from TI"
  enabled                    = true
  severity                   = "Medium"
  query                      = <<QUERY
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(Url)
| join (
  AuditLogs
  | where TimeGenerated >= ago(dt_lookBack)
  // Extract the URL that is contained within the JSON data
  | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+);", 1,tostring(TargetResources))
  | where isnotempty(Url)
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend TargetResourceDisplayName = tostring(TargetResources[0].displayName)
  | extend Audit_TimeGenerated = TimeGenerated
) on Url
| where Audit_TimeGenerated >= TimeGenerated and Audit_TimeGenerated < ExpirationDateTime
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore,
Audit_TimeGenerated, OperationName, Identity, userPrincipalName, TargetResourceDisplayName, Url
| extend timestamp = Audit_TimeGenerated, AccountCustomEntity = userPrincipalName, HostCustomEntity = TargetResourceDisplayName, URLCustomEntity = Url
QUERY
  query_frequency            = "PT1H"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host", "Url"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# Scheduled - Low
# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_attempt_to_bypass_conditional_access_rule_in_AAD" {
  name                       = "sdr_attempt_to_bypass_conditional_access_rule_in_AAD"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Attempt to bypass conditional access rule in Azure AD"
  description                = "Identifies an attempt to Bypass conditional access rule(s) in Azure Active Directory. The ConditionalAccessStatus column value details if there was an attempt to bypass Conditional Access or if the Conditional access rule was not satisfied (ConditionalAccessStatus == 1). References: https://docs.microsoft.com/azure/active-directory/conditional-access/overview https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes ConditionalAccessStatus == 0 // Success ConditionalAccessStatus == 1 // Failure ConditionalAccessStatus == 2 // Not Applied ConditionalAccessStatus == 3 // unknown"
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let threshold = 1;
let aadFunc = (tableName:string){
table(tableName)
| where ConditionalAccessStatus == 1 or ConditionalAccessStatus =~ "failure"
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend ConditionalAccessPolicies = todynamic(ConditionalAccessPolicies)
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName)
| extend Status = strcat(StatusCode, ": ", ResultDescription)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), Status = make_list(Status), StatusDetails = make_list(StatusDetails), IPAddresses = make_list(IPAddress), IPAddressCount = dcount(IPAddress), CorrelationIds = make_list(CorrelationId)
by UserPrincipalName, AppDisplayName, tostring(Browser), tostring(OS), City, State, Region, ConditionalAccessPol0Name, ConditionalAccessPol1Name, ConditionalAccessPol2Name, Type
| where IPAddressCount > threshold and StatusDetails !has "MFA successfully completed"
| mvexpand IPAddresses, Status, StatusDetails, CorrelationIds
| extend Status = strcat(Status, " ", StatusDetails)
| summarize IPAddresses = make_set(IPAddresses), Status = make_set(Status), CorrelationIds = make_set(CorrelationIds)
by StartTime, EndTime, UserPrincipalName, AppDisplayName, tostring(Browser), tostring(OS), City, State, Region, ConditionalAccessPol0Name, ConditionalAccessPol1Name, ConditionalAccessPol2Name, IPAddressCount, Type
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = tostring(IPAddresses)
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess", "Persistence"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_creation_of_expensive_computes_in_azure" {
  name                       = "sdr_creation_of_expensive_computes_in_azure"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Creation of expensive computes in Azure"
  description                = "Identifies the creation of large size/expensive VMs (GPU or with large no of virtual CPUs) in Azure. Adversary may create new or update existing virtual machines sizes to evade defenses or use it for cryptomining purposes. For Windows/Linux Vm Sizes - https://docs.microsoft.com/azure/virtual-machines/windows/sizes Azure VM Naming Conventions - https://docs.microsoft.com/azure/virtual-machines/vm-naming-conventions"
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let tokens = dynamic(["416","208","128","120","96","80","72","64","48","44","40","g5","gs5","g4","gs4","nc12","nc24","nv12"]);
let operationList = dynamic(["Create or Update Virtual Machine", "Create Deployment"]);
AzureActivity
| where OperationName in (operationList)
| where ActivityStatus == "Accepted"
| where isnotempty(Properties)
| extend vmSize = tolower(tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).hardwareProfile)).vmSize))
| where isnotempty(vmSize)
| where vmSize has_any (tokens)
| extend ComputerName = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).osProfile)).computerName)
| extend clientIpAddress = tostring(parse_json(HTTPRequest).clientIpAddress)
| project TimeGenerated, OperationName, ActivityStatus, Caller, CallerIpAddress, ComputerName, vmSize, ResourceId
| extend timestamp = TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
QUERY
  query_frequency            = "PT12H"
  query_period               = "PT12H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 1
  suppression_enabled        = false
  tactics                    = ["DefenseEvasion"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_failed_login_attempts_to_azure_portal" {
  name                       = "sdr_failed_login_attempts_to_azure_portal"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Failed login attempts to Azure Portal"
  description                = "Identifies failed login attempts in the Azure Active Directory SigninLogs to the Azure Portal. Many failed logon attempts or some failed logon attempts from multiple IPs could indicate a potential brute force attack. The following are excluded due to success and non-failure results: References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes 0 - successful logon 50125 - Sign-in was interrupted due to a password reset or password registration entry. 50140 - This error occurred due to 'Keep me signed in' interrupt when the user was signing-in."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let timeRange = 1d;
let lookBack = 7d;
let threshold_Failed = 5;
let threshold_FailedwithSingleIP = 20;
let threshold_IPAddressCount = 2;
let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}";
let aadFunc = (tableName:string){
let azPortalSignins = materialize(table(tableName)
| where TimeGenerated >= ago(lookBack)
// Azure Portal only
| where AppDisplayName =~ "Azure Portal")
;
let successPortalSignins = azPortalSignins
| where TimeGenerated >= ago(timeRange)
// Azure Portal only and exclude non-failure Result Types
| where ResultType in ("0", "50125", "50140")
// Tagging identities not resolved to friendly names
//| extend Unresolved = iff(Identity matches regex isGUID, true, false)
| distinct TimeGenerated, UserPrincipalName, Id, ResultType
;
let failPortalSignins = azPortalSignins
| where TimeGenerated >= ago(timeRange)
// Azure Portal only and exclude non-failure Result Types
| where ResultType !in ("0", "50125", "50140")
// Tagging identities not resolved to friendly names
| extend Unresolved = iff(Identity matches regex isGUID, true, false)
;
// Verify there is no success for the same connection attempt after the fail
let failnoSuccess = failPortalSignins | join kind= leftouter (
successPortalSignins
) on UserPrincipalName, Id
| where TimeGenerated > TimeGenerated1
| project-away TimeGenerated1, UserPrincipalName1, Id1, ResultType1
;
// Lookup up resolved identities from last 7 days
let identityLookup = azPortalSignins
| where TimeGenerated >= ago(lookBack)
| where not(Identity matches regex isGUID)
| summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName;
// Join resolved names to unresolved list from portal signins
let unresolvedNames = failnoSuccess | where Unresolved == true | join kind= inner (
identityLookup
) on UserId
| extend UserDisplayName = lu_UserDisplayName, UserPrincipalName = lu_UserPrincipalName
| project-away lu_UserDisplayName, lu_UserPrincipalName;
// Join Signins that had resolved names with list of unresolved that now have a resolved name
let u_azPortalSignins = failnoSuccess | where Unresolved == false | union unresolvedNames;
u_azPortalSignins
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend Status = strcat(ResultType, ": ", ResultDescription), OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
| extend FullLocation = strcat(Region,'|', State, '|', City)
| summarize TimeGenerated = makelist(TimeGenerated), Status = makelist(Status), IPAddresses = makelist(IPAddress), IPAddressCount = dcount(IPAddress), FailedLogonCount = count()
by UserPrincipalName, UserId, UserDisplayName, AppDisplayName, Browser, OS, FullLocation, Type
| mvexpand TimeGenerated, IPAddresses, Status
| extend TimeGenerated = todatetime(tostring(TimeGenerated)), IPAddress = tostring(IPAddresses), Status = tostring(Status)
| project-away IPAddresses
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, UserId, UserDisplayName, Status, FailedLogonCount, IPAddress, IPAddressCount, AppDisplayName, Browser, OS, FullLocation, Type
| where (IPAddressCount >= threshold_IPAddressCount and FailedLogonCount >= threshold_Failed) or FailedLogonCount >= threshold_FailedwithSingleIP
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
QUERY
  query_frequency            = "P1D"
  query_period               = "P7D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_interactive_sts_refresh_token_modifications" {
  name                       = "sdr_interactive_sts_refresh_token_modifications"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Interactive STS refresh token modifications"
  description                = "This will show Active Directory Security Token Service (STS) refresh token modifications by Service Principals and Applications other than DirectorySync. Refresh tokens are used to validate identification and obtain access tokens. This event is most often generated when legitimate administrators troubleshoot frequent AAD user sign-ins but may also be generated as a result of malicious token extensions. Confirm that the activity is related to an administrator legitimately modifying STS refresh tokens and check the new token validation time period for high values. For in-depth documentation of AAD Security Tokens, see https://docs.microsoft.com/azure/active-directory/develop/security-tokens. For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let auditLookback = 1d;
AuditLogs
| where TimeGenerated > ago(auditLookback)
| where OperationName has 'StsRefreshTokenValidFrom'
| where TargetResources[0].modifiedProperties != '[]'
| where TargetResources[0].modifiedProperties !has 'DirectorySync'
| extend TargetResourcesModProps = TargetResources[0].modifiedProperties
| mv-expand TargetResourcesModProps
| where tostring(TargetResourcesModProps.displayName) =~ 'StsRefreshTokensValidFrom'
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| where InitiatingUserOrApp !in ('Microsoft Cloud App Security')
| extend targetUserOrApp = TargetResources[0].userPrincipalName
| extend eventName = tostring(TargetResourcesModProps.displayName)
| extend oldStsRefreshValidFrom = todatetime(parse_json(tostring(TargetResourcesModProps.oldValue))[0])
| extend newStsRefreshValidFrom = todatetime(parse_json(tostring(TargetResourcesModProps.newValue))[0])
| extend tokenMinutesAdded = datetime_diff('minute',newStsRefreshValidFrom,oldStsRefreshValidFrom)
| extend tokenMinutesRemaining = datetime_diff('minute',TimeGenerated,newStsRefreshValidFrom)
| project-reorder Result, AADOperationType
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_multiple_password_reset_by_user" {
  name                       = "sdr_multiple_password_reset_by_user"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Multiple Password Reset by user"
  description                = "This query will determine multiple password resets by user across multiple data sources. Account manipulation including password reset may aid adversaries in maintaining access to credentials and certain permission levels within an environment."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let PerUserThreshold = 5;
let TotalThreshold = 100;
let action = dynamic(["change", "changed", "reset"]);
let pWord = dynamic(["password", "credentials"]);
let PasswordResetMultiDataSource =
(union isfuzzy=true
(//Password reset events
//4723: An attempt was made to change an account's password
//4724: An attempt was made to reset an accounts password
SecurityEvent
| where EventID in ("4723","4724")
| project TimeGenerated, Computer, AccountType, Account, Type),
(//Azure Active Directory Password reset events
AuditLogs
| where OperationName has_any (pWord) and OperationName has_any (action)
| extend AccountType = tostring(TargetResources[0].type), Account = tostring(TargetResources[0].userPrincipalName),
TargetResourceName = tolower(tostring(TargetResources[0].displayName))
| project TimeGenerated, AccountType, Account, Computer = TargetResourceName, Type),
(//OfficeActive ActiveDirectory Password reset events
OfficeActivity
| where OfficeWorkload == "AzureActiveDirectory"
| where (ExtendedProperties has_any (pWord) or ModifiedProperties has_any (pWord)) and (ExtendedProperties has_any (action) or ModifiedProperties has_any (action))
| extend AccountType = UserType, Account = OfficeObjectId
| project TimeGenerated, AccountType, Account, Type, Computer = ""),
(// Unix syslog password reset events
Syslog
| where Facility in ("auth","authpriv")
| where SyslogMessage has_any (pWord) and SyslogMessage has_any (action)
| extend AccountType = iif(SyslogMessage contains "root", "Root", "Non-Root")
| parse SyslogMessage with * "password changed for" Account
| project TimeGenerated, AccountType, Account, Computer = HostName, Type),
(SigninLogs
| where OperationName =~ "Sign-in activity" and ResultType has_any ("50125", "50133")
| project TimeGenerated, AccountType = AppDisplayName, Computer = IPAddress, Account = UserPrincipalName, Type
)
);
let pwrmd = PasswordResetMultiDataSource
| project TimeGenerated, Computer, AccountType, Account, Type;
(union isfuzzy=true
(pwrmd
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Computer = makeset(Computer), AccountType = makeset(AccountType), Total=count() by Account, Type
| where Total > PerUserThreshold
| extend ResetPivot = "PerUserReset"),
(pwrmd
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Computer = makeset(Computer), Account = tostring(makeset(Account)), AccountType = makeset(AccountType), Total=count() by Type
| where Total > TotalThreshold
| extend ResetPivot = "TotalUserReset")
)
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = tostring(Computer)
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["InitialAccess", "CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Host"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_new_cloudshell_user" {
  name                       = "sdr_new_cloudshell_user"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "New CloudShell User"
  description                = "Identifies when a user creates an Azure CloudShell for the first time. Monitor this activity to ensure only expected user are using CloudShell."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
AzureActivity
| extend message = tostring(parse_json(Properties).message)
| extend AppId = tostring(parse_json(Claims).appid)
| where AppId contains "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
| where OperationName =~ "Microsoft.Portal/consoles/write"
| extend timestamp = TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Execution"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_rare_subscription_level_operations_in_azure" {
  name                       = "sdr_rare_subscription_level_operations_in_azure"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Rare subscription-level operations in Azure"
  description                = "This query looks for a few sensitive subscription-level events based on Azure Activity Logs. For example this monitors for the operation name 'Create or Update Snapshot' which is used for creating backups but could be misused by attackers to dump hashes or extract sensitive information from the disk."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let starttime = 14d;
let endtime = 1d;
// The number of operations below which an IP address is considered an unusual source of role assignment operations
let alertOperationThreshold = 5;
let SensitiveOperationList = dynamic(
["List keys", "List Storage Account Keys", "Register Subscription", "Create or Update Snapshot", "Create or Update Network Security Group"]);
let SensitiveActivity = AzureActivity
| where OperationName in~ (SensitiveOperationList)
| where ActivityStatus =~ "Succeeded";
SensitiveActivity
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| summarize count() by CallerIpAddress, Caller
| where count_ >= alertOperationThreshold
| join kind = rightanti (
SensitiveActivity
| where TimeGenerated >= ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatus = makelist(ActivityStatus),
OperationIds = makelist(OperationId), CorrelationIds = makelist(CorrelationId), Resources = makelist(Resource), ResourceGroups = makelist(ResourceGroup), ResourceIds = makelist(ResourceId), ActivityCountByCallerIPAddress = count()
by CallerIpAddress, Caller, OperationName
) on CallerIpAddress, Caller
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess", "Persistence"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_application_consent_for_offline_access" {
  name                       = "sdr_suspicious_application_consent_for_offline_access"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious application consent for offline access"
  description                = "This will alert when a user consents to provide a previously-unknown Azure application with offline access via OAuth. Offline access will provide the Azure App with access to the listed resources without requiring two-factor authentication. Consent to applications with offline access and read capabilities should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome! For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "offline"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "offline_access" and ConsentFull contains "Files.Read" or ConsentFull contains "Mail.Read" or ConsentFull contains "Notes.Read" or ConsentFull contains "ChannelMessage.Read" or ConsentFull contains "Chat.Read" or ConsentFull contains "TeamsActivity.Read" or ConsentFull contains "Group.Read" or ConsentFull contains "EWS.AccessAsUser.All" or ConsentFull contains "EAS.AccessAsUser.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = tostring(iff(isnotempty(InitiatedBy.user.userPrincipalName),InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend GrantUserAgent = tostring(iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, ""))
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["CredentialAccess"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}

# TBM - Set logic rule(custom details), Automated response
resource "azurerm_sentinel_alert_rule_scheduled" "sdr_suspicious_resource_deployment" {
  name                       = "sdr_suspicious_resource_deployment"
  log_analytics_workspace_id = module.log_analytics_workspace.log_analytics_workspace_id
  display_name               = "Suspicious Resource deployment"
  description                = "Identifies when a rare Resource and ResourceGroup deployment occurs by a previously unseen Caller."
  enabled                    = true
  severity                   = "Low"
  query                      = <<QUERY
let szOperationNames = dynamic(["Create or Update Virtual Machine", "Create Deployment"]);
let starttime = 14d;
let endtime = 1d;
let RareCaller = AzureActivity
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| where OperationName in~ (szOperationNames)
| project ResourceGroup, Caller, OperationName, CallerIpAddress
| join kind=rightantisemi (
AzureActivity
| where TimeGenerated > ago(endtime)
| where OperationName in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityStatus = makeset(ActivityStatus), OperationIds = makeset(OperationId), CallerIpAddress = makeset(CallerIpAddress)
by ResourceId, Caller, OperationName, Resource, ResourceGroup
) on Caller, ResourceGroup
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress);
let Counts = RareCaller | summarize ActivityCountByCaller = count() by Caller;
RareCaller | join kind= inner (Counts) on Caller | project-away Caller1
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = tostring(CallerIpAddress)
| sort by ActivityCountByCaller desc nulls last
QUERY
  query_frequency            = "P1D"
  query_period               = "P14D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = ["Impact"]
  event_grouping {
    aggregation_method = "SingleAlert"
  }
  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "All"
      group_by                = ["Account", "Ip"]
    }
  }
  depends_on = [module.log_analytics_workspace, azurerm_log_analytics_solution.la_opf_solution_sentinel]
}
