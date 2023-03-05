#requires -version 6.2
<#
    .SYNOPSIS
        This command will generate a CSV file containing the names of all the Azure Sentinel
        rules that need updating
    .DESCRIPTION
        This command will generate a CSV file containing the names of all the Azure Sentinel
        rules that need updating
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to use.  Defaults to "solutionInformation.csv"  ".csv" will be appended to all filenames
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 19 Feb 2023
    .EXAMPLE
        Update-AzSentinelRulesFromCSV "workspacename" -ResourceGroupName "rgname"
        In this example you will get the file named "rulesNeedingUpdates.csv" generated containing all the solution information
    .EXAMPLE
        Update-AzSentinelRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
        In this example you will get the file named "test.csv" generated containing all the solution information
   
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [string]$FileName = "rulesNeedingUpdates.csv"

)
Function Update-AzSentinelRulesFromCSV ($workspaceName, $resourceGroupName, $fileName) {

    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $instanceProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($instanceProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    $subscriptionId = $context.Subscription.Id

    #Load the MS Sentinel rule templates so that we search for the information we need
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2023-02-01-preview"
    $ruleTemplates = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the rule templates from solutions
    $solutionURL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    $query = @"
    Resources 
    | where type =~ 'Microsoft.Resources/templateSpecs/versions' 
    | where tags['hidden-sentinelContentType'] =~ 'AnalyticsRule' 
    and tags['hidden-sentinelWorkspaceId'] =~ '/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)' 
    | extend version = name 
    | extend parsed_version = parse_version(version) 
    | extend resources = parse_json(parse_json(parse_json(properties).template).resources) 
    | extend metadata = parse_json(resources[array_length(resources)-1].properties)
    | extend contentId=tostring(metadata.contentId) 
    | summarize arg_max(parsed_version, version, properties) by contentId 
    | project contentId, version, properties
"@
    $body = @{
        "subscriptions" = @($SubscriptionId)
        "query"         = $query
    }
    $solutionTemplates = Invoke-RestMethod -Uri $solutionURL -Method POST -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)

    #Load the file of the rules to update
    #Load the MSS timing and grouping modifications
    $rulesToUpdate = Import-Csv $fileName

    $ruleType = ""
    $foundTemplate = ""

    #Check each rule
    foreach ($rule in $rulesToUpdate) {

        if (($rule.Update -eq "A") -or ($rule.Update -eq "P") -or ($rule.Update -eq "V")) {

            $foundTemplate = $ruleTemplates | Where-Object -Property "name" -EQ $rule.TemplateId
            #If not found, check the solution rule templates
            if ($null -eq $foundTemplate) {
                $foundTemplate = ($solutionTemplates.data | Where-Object -Property "contentId" -EQ $rule.TemplateId)
                $ruleType = $foundTemplate.properties.template.resources.kind
                $foundTemplate = $foundTemplate.properties.template.resources.properties[0]
            }
            else {
                $ruleType = $foundTemplate.kind
                $foundTemplate = $foundTemplate.properties
            }


            #We need to load the rule in question in case the fields we don't want to update are some of the required fields
            #needed for an update
            $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertrules/$($rule.RuleId)?api-version=2022-12-01-preview"
            $ruleToUpdate = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).properties

            $body = ""

            #Setup variables for the needed variables.
            $displayName = $foundTemplate.displayName
            $displayName = $ruleToUpdate.displayName
            if ($rule.DisplayNameChanged -eq "True" -or ($rule.update -eq "A")) { $displayName = $foundTemplate.displayName }

            $description = $ruleToUpdate.description
            if ($rule.DescriptionChanged -eq "True" -or ($rule.update -eq "A")) { $description = $foundTemplate.description }

            $severity = $ruleToUpdate.severity
            if ($rule.SeverityChanged -eq "True" -or ($rule.update -eq "A")) { $severity = $foundTemplate.severity }

            $tactics = $ruleToUpdate.tactics
            if ($rule.TacticsChanged -eq "True" -or ($rule.update -eq "A")) { $tactics = $foundTemplate.tactics }

            $techniques = $ruleToUpdate.techniques
            if ($rule.TechniquesChanged -eq "True" -or ($rule.update -eq "A")) { $techniques = $foundTemplate.techniques }

            $query = $ruleToUpdate.query
            if ($rule.QueryChanged -eq "True" -or ($rule.update -eq "A")) { $query = $foundTemplate.query }

            $queryFrequency = $ruleToUpdate.queryFrequency
            if ($rule.QueryFrequencyChanged -eq "True" -or ($rule.update -eq "A")) { $queryFrequency = $foundTemplate.queryFrequency }

            $queryPeriod = $ruleToUpdate.queryPeriod
            if ($rule.QueryPeriodChanged -eq "True" -or ($rule.update -eq "A")) { $queryPeriod = $foundTemplate.queryPeriod }

            $triggerOperator = $ruleToUpdate.triggerOperator
            if ($rule.TriggerOperatorChanged -eq "True" -or ($rule.update -eq "A")) { $triggerOperator = $foundTemplate.triggerOperator }

            $triggerThreshold = $ruleToUpdate.triggerThreshold
            if ($rule.TriggerThresholdChanged -eq "True" -or ($rule.update -eq "A")) { $triggerThreshold = $foundTemplate.triggerThreshold }

            $entityMappings = $ruleToUpdate.entityMappings
            if ($rule.EntityMappingsChanged -eq "True" -or ($rule.update -eq "A")) { $entityMappings = $foundTemplate.entityMappings }

            $customDetails = $ruleToUpdate.customDetails

            $alertDetailName = $ruleToUpdate.alertDetailsOverride.AlertDetailNameChanged
            if ($rule.AlertDetailNameChanged -eq "True" -or ($rule.update -eq "A")) { $alertDetailName = $foundTemplate.alertDetailsOverride.alertDetailNameFormat }

            $alertDescriptionFormat = $ruleToUpdate.alertDetailsOverride.alertDescriptionFormat
            if ($rule.AlertDetailDescriptionChanged -eq "True" -or ($rule.update -eq "A")) { $alertDescriptionFormat = $foundTemplate.alertDetailsOverride.alertDescriptionFormat }

            $ruleAlertDetailDynamic = $ruleToUpdate.alertDetailsOverride.ruleAlertDetailDynamic
            if ($rule.AlertDetailDynamicPropertiesChanged -eq "True" -or ($rule.update -eq "A")) { $ruleAlertDetailDynamic = $rufoundTemplateleToUpdate.alertDetailsOverride.alertDynamicProperties }

            $suppressionDuration = $ruleToUpdate.suppressionDuration
            if ($rule.suppressionDurationChanged -eq "True" -or ($rule.update -eq "A")) { $suppressionDuration = $foundTemplate.suppressionDuration }

            $suppressionEnabled = $ruleToUpdate.suppressionEnabled
            if ($rule.suppressionEnabledChanged -eq "True" -or ($rule.update -eq "A")) { $suppressionEnabled = $foundTemplate.suppressionEnabled }

            $eventGroupSettings = $ruleToUpdate.eventGroupingSettings
            if ($rule.eventGroupSettingsChanged -eq "True" -or ($rule.update -eq "A")) { $eventGroupSettings = $foundTemplate.eventGroupSettings }

            $enabled = $ruleToUpdate.enabled

            # Check to see what we want to do with each rule
            # Update either all the fields or just the selected ones
            if (($rule.Update -eq "A") -or ($rule.Update -eq "P")) {
                if ($ruleType -eq "Scheduled") {
                    $body = @{
                        "properties" = @{
                            "displayName"           = $displayName
                            "description"           = $description
                            "enabled"               = $enabled
                            "tactics"               = $tactics
                            "techniques"            = $techniques
                            "query"                 = $query
                            "queryFrequency"        = $queryFrequency
                            "queryPeriod"           = $queryPeriod
                            "severity"              = $severity
                            "triggerOperator"       = $triggerOperator
                            "triggerThreshold"      = $triggerThreshold
                            "entityMappings"        = $entityMappings
                            "customDetails"         = $customDetails
                            "suppressionDuration"   = $suppressionDuration
                            "suppressionEnabled"    = $suppressionEnabled
                            "eventGroupSettings"    = $eventGroupSettings
                            "alertDetailsOverride"  = @{
                                "alertDetailName"        = $alertDetailName
                                "alertDescriptionFormat" = $alertDescriptionFormat
                                "ruleAlertDetailDynamic" = $ruleAlertDetailDynamic
                            }
                            "alertRuleTemplateName" = $ruleToUpdate.alertRuleTemplateName
                            "templateVersion"       = $rule.NewVersion
                        }
                    }
                }
                elseif ($ruleType -eq "NRT") {
                    $body = @{
                        "kind"       = "NRT"
                        "properties" = @{
                            "displayName"           = $displayName
                            "description"           = $description
                            "enabled"               = $enabled
                            "tactics"               = $tactics
                            "techniques"            = $techniques
                            "query"                 = $query
                            "severity"              = $severity
                            "entityMappings"        = $entityMappings
                            "suppressionDuration"   = $suppressionDuration
                            "suppressionEnabled"    = $suppressionEnabled
                            "eventGroupSettings"    = $eventGroupSettings
                            "alertRuleTemplateName" = $ruleToUpdate.alertRuleTemplateName
                            "templateVersion"       = $rule.NewVersion
                        }
                    }
                }
            }
            # Just update the version number.  These are the minimal fields required.
            elseif ($rule.Update -eq "V") {
                if ($ruleType -eq "Scheduled") {
                    $body = @{
                        "properties" = @{
                            "queryFrequency"        = $ruleToUpdate.queryFrequency
                            "queryPeriod"           = $ruleToUpdate.queryPeriod
                            "triggerOperator"       = $ruleToUpdate.triggerOperator
                            "triggerThreshold"      = $ruleToUpdate.triggerThreshold
                            "severity"              = $ruleToUpdate.severity
                            "query"                 = $ruleToUpdate.query
                            "suppressionDuration"   = $ruleToUpdate.suppressionDuration
                            "suppressionEnabled"    = $ruleToUpdate.suppressionEnabled
                            "displayName"           = $ruleToUpdate.displayName
                            "enabled"               = $enabled
                            "alertRuleTemplateName" = $ruleToUpdate.alertRuleTemplateName
                            "templateVersion"       = $rule.NewVersion
                        }
                    }
                }
                elseif ($ruleType -eq "NRT") {
                    $body = @{
                        "kind"       = "NRT"
                        "properties" = @{
                            "queryFrequency"        = $ruleToUpdate.queryFrequency
                            "queryPeriod"           = $ruleToUpdate.queryPeriod
                            "triggerOperator"       = $ruleToUpdate.triggerOperator
                            "triggerThreshold"      = $ruleToUpdate.triggerThreshold
                            "severity"              = $ruleToUpdate.severity
                            "query"                 = $ruleToUpdate.query
                            "suppressionDuration"   = $ruleToUpdate.suppressionDuration
                            "suppressionEnabled"    = $ruleToUpdate.suppressionEnabled
                            "displayName"           = $ruleToUpdate.displayName
                            "enabled"               = $enabled
                            "alertRuleTemplateName" = $ruleToUpdate.alertRuleTemplateName
                            "templateVersion"       = $rule.NewVersion
                        }
                    }
                }
                # if the Update is "N" or empty, we will not do anything
            }

            $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertrules/$($rule.RuleId)?api-version=2022-12-01-preview"

            try {
                Write-Host "Attempting to update rule $($displayName)"
                $verdict = Invoke-RestMethod -Uri $uri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)
                Write-Output "Succeeded"
            }
            catch {
                #The most likely error is that there is a missing dataset. There is a new
                #addition to the REST API to check for the existance of a dataset but
                #it only checks certain ones.  Hope to modify this to do the check
                #before trying to create the alert.
                $errorReturn = $_
                Write-Error $errorReturn
            }
        }
    }
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
Update-AzSentinelRulesFromCSV $WorkSpaceName $ResourceGroupName $FileName 
