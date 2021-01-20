<#
    .SYNOPSIS
    Creates an overview of the existing role assignments within Azure RBAC. Can be extremely usefull to determine who has access at which scope and what permissions
    .DESCRIPTION
    Queries the role assignments on different Azure RBAC levels:
    - Management Groups
    - Subscriptions
    - Resource Groups
    - Resources
    
    Shows details about permission inheritance from parent to child levels
    Provides insight in permissions aquired by means of group memberships
    Exports the results in both a hierarchical (JSON) and flat structure (CSV). The former does provide the most detailed information

    NOTE: In order to retrieve all the information from both Azure RBAC and Azure AD, you'll need an account that has permissions to request the role assignments:
    - In case you're using management groups: On the root management groups
    - If not: On the subscriptions
    And list the details of identities within Azure AD.

    .OUTPUTS
    This script will save the results in the current directory, unless another path has been provided in the OutputPath parameter
    .JSON format, which contains the resource and groupmembership hierarchy 
    .CSV format, containing a flat structure
    .PARAMETER ExcludeResources
    [OPTIONAL] When using this parameter, all resources will be skipped
    .PARAMETER ExcludeResourceGroups
    [OPTIONAL] When using this parameter, all resource groups and children (e.g. resources) will be skipped. So the ExcludeResources parameter is not interpreted when this parameter is used
    .PARAMETER ExcludeSubscriptions
    [OPTIONAL] When using this parameter, all subscriptions and children (e.g. resource groups and resources) will be skipped. So the ExcludeResourceGroups and ExcludeResources parameters are not interpreted when this parameter is used
    .PARAMETER IncludeInheritedRoleAssignments
    [OPTIONAL] Within Azure RBAC permissions will be propagated to child objects (Management Group -> Subscription > Resource Group > Resources). 
    Setting this parameter will include inherited permissions within the results.
    .PARAMETER IncludeGroupMemberships
    [OPTIONAL] When roles are assigned to a group, the role assignment is also applicable to all members of the group. 
    Setting this parameter will include these group memberships within the results.
    .PARAMETER OutputPath
    [OPTIONAL] The output of the script is saved in the current directoy, unless another location has been provided using this parameter

    .EXAMPLE
    .\AzurePermissionInsight.ps1
    .EXAMPLE
    .\AzurePermissionInsight.ps1 -ExcludeSubscriptions
    .EXAMPLE
    .\AzurePermissionInsight.ps1 -ExcludeResources -OutputPath "C:\Temp"
    .NOTES
    Azure RBAC permission insight
    By Sebastiaan van Putten / Seb8iaan.com
    Version History:
    V1.0, 18-01-2021 - Initial version
#>

[CmdletBinding()]
param(
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeResources=$FALSE,
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeResourceGroups=$FALSE,
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeSubscriptions=$FALSE,
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$IncludeInheritedRoleAssignments=$FALSE,
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$IncludeGroupMemberships=$FALSE,
    [parameter(Mandatory=$false,ValueFromPipeline=$false)][string]$OutputPath=$($PWD.Path)
)

Function Import-AzureInSightModules
{
    [CmdletBinding()]
    Param(
        $RequiredModules = @("Az.Accounts","Az.Resources")
    )

    ForEach ($RequiredModule in $RequiredModules)
    {
        If (!(Get-Module $RequiredModule -ListAvailable -ErrorAction SilentlyContinue))
        {
            Write-Verbose "Required module, $RequiredModule, is not installed on the system."

            Write-Verbose "Installing required module from default repository: $RequiredModule "
            Install-Module -Name $RequiredModule -Scope CurrentUser -Force

            Write-Verbose "Importing required module: $RequiredModule"
            Import-Module -Name $RequiredModule
        } 
        ElseIf (!(Get-Module $RequiredModule -ErrorAction SilentlyContinue))
        {
            Write-Verbose "Required module, $RequiredModule, is installed on the system."

            Write-Verbose "Importing required module: $RequiredModule"
            Import-Module -Name $RequiredModule
        }
    }
}
Function Connect-AzureInsight
{
    [CmdletBinding(DefaultParameterSetName = 'ModernAuth')]
    Param(
        [Parameter(ParameterSetName = 'ModernAuth')]
        [switch]$ModernAuth,

        [Parameter(ParameterSetName = 'SPNAuth')]
        [switch]$ServicePrincipalAuth,

        [Parameter(ParameterSetName = 'SPNAuth', Mandatory=$false)]
        [System.Management.Automation.PSCredential]$ServicePrincipalCredential,

        [Parameter(ParameterSetName = 'ModernAuth', Mandatory=$false)]
        [Parameter(ParameterSetName = 'SPNAuth', Mandatory=$true)]
        [string]$TenantID
    )

    If($ModernAuth -or (!$ModernAuth -and !$ServicePrincipalAuth))
    {
        if($TenantID)
        {
            try
            {
                Connect-AzAccount -tenantid $TenantID -ErrorAction STOP| Out-Null
            }
            catch
            {
                $Global:AzureInsightConnectedError = $TRUE
            }
        }
        else 
        {
            try {
                Connect-AzAccount -ErrorAction STOP | Out-Null
            }
            catch 
            {
                $Global:AzureInsightConnectedError = $TRUE
            }
        }
    }
    elseif($ServicePrincipalAuth)
    {
        if(!$ServicePrincipalCredential)
        {
            $ServicePrincipalCredential = Get-Credential -Message "Provide the ApplicationID and Secret of the Service Principal"
        }

        if($TenantID)
        {
            try 
            {
                Connect-AzAccount -ServicePrincipal -Credential $ServicePrincipalCredential -tenantid $TenantID -ErrorAction STOP | Out-Null
            }
            catch
            {
                $Global:AzureInsightConnectedError = $TRUE
            }
        }
        else 
        {
            try {
                Connect-AzAccount -ServicePrincipal -Credential $ServicePrincipalCredential -ErrorAction STOP  | Out-Null
            }
            catch {
                $Global:AzureInsightConnectedError = $TRUE
            }
        }
    }

    if($Global:AzureInsightConnectedError -eq $TRUE)
    {
        Write-Error `
        -Exception "Connection to Azure could not be established" `
        -Message "Connection to Azure could not be established"

        Remove-AzureInSightVariables

        exit
    }
    else 
    {
        $Global:AzureInsightConnected = $TRUE
    }
}

Function Out-AzureInSightToFile
{
    param(
        [String]$Type,
        $Value,
        $Mode
    )

    #region Initialize Output Directory

    if(!$Global:AzureInsightLogDirectory)
    {
        $ExecutionTime = Get-Date -Format "yyyyMMddTHHmm"
        $ExecutionFolder = "$($OutputPath)\$($ExecutionTime)_AzureInsight"
            
        if (-not (Test-Path -Path $ExecutionFolder)) 
        {
            Write-Verbose "Creating new folder: $($ExecutionFolder)"
            New-Item -Path $ExecutionFolder -ItemType "directory" | Out-Null
            $Global:AzureInsightLogDirectory = $ExecutionFolder
        }
    }
    #endregion Initialize Output Directory

    $LogFile = "AzureInsight_$($Mode)"

    Switch ($Type)
    {
        "CSV"
        {
            $FullLogFilePath = "$($Global:AzureInsightLogDirectory)\$($LogFile).CSV"
            Write-Verbose "File will be written to $($FullLogFilePath)"

            $Value | Export-CSV -Path $FullLogFilePath -NoTypeInformation
        }
        "HTML"
        {
            <# to be implemented
            #>
        }
        "JSON"
        {
            $FullLogFilePath = "$($Global:AzureInsightLogDirectory)\$($LogFile).JSON"
            Write-Verbose "File will be written to $($FullLogFilePath)"

            $Value | ConvertTo-JSOn -depth 99 | Set-Content -Path $FullLogFilePath
        
        }
        default
        {
            Write-Error `
            -Exception "File type unknown" `
            -RecommendedAction "Provide a file type: CSV, HTML or JSON" `
            -Message "The provided file type is not known"
        }
    }
}

Function Remove-AzureInSightVariables
{
    $Global:AzureInsightConnected = $NULL
    $Global:AzureInsightLogDirectory = $NULL
    $Global:AzureInsightFlatResults = $NULL
    $Global:AzureInsightConnectedError = $NULL
}

Function Get-AzureInSightPermissions
{
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeResources=$FALSE,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeResourceGroups=$FALSE,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$ExcludeSubscriptions=$FALSE,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$IncludeInheritedRoleAssignments=$FALSE,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][switch]$IncludeGroupMemberships=$FALSE,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][string]$Mode="AzureRBAC",
        [parameter(Mandatory=$false,ValueFromPipeline=$false)][string]$OutputPath=$($PWD.Path)
    )

    If($Mode -eq "AzureRBAC")
    {
        $AzureInSightPermissions =  Get-AzureInSightManagementGroup `
                            -ExcludeResources:$ExcludeResources `
                            -ExcludeResourceGroups:$ExcludeResourceGroups `
                            -ExcludeSubscriptions:$ExcludeSubscriptions `
                            -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                            -IncludeGroupMemberships:$IncludeGroupMemberships


        Out-AzureInSightToFile `
        -Type "JSON" `
        -Value $AzureInSightPermissions `
        -Mode $Mode

        Out-AzureInSightToFile `
        -Type "CSV" `
        -Value $Global:AzureInsightFlatResults `
        -Mode $Mode

        return $Permissions
    }
    else 
    {
        Write-Error `
            -Exception "Unknown Mode" `
            -RecommendedAction "Provide a supported mode" `
            -Message "The provided mode is not known"

        return $NULL
    }
}

Function Switch-AzureInsightSupportedContext
{
    [CmdletBinding()]
    param()

    try {
        write-verbose "Verifying if the current subscription type is permitted to perform operations on any provider namespace"
        $TempVariable = Get-AzRoleAssignment -ErrorAction "Stop"
    }
    catch {
        write-verbose "The current subscription type is not permitted to perform operations on any provider namespace, switching context"

        $Subscriptions = Get-AzSubscription
        $SupportedSubscription = $Subscriptions | where{($_.SubscriptionPolicies.QuotaId.StartsWith('AAD') -eq $FALSE) -and $_.State -eq "Enabled"} | Select -First 1
        if($SupportedSubscription)
        {
            write-verbose "Switching to context: $($SupportedSubscription.name)"
            Set-AzContext $SupportedSubscription | Out-Null
        }
        else 
        {
            Write-Error `
            -Exception "No supported subscription found"  `
            -RecommendedAction "Set the context to a non-Office365 subscription" `
            -Message "No supported subscription found"
        }
    }
}

Function Get-AzureInSightManagementGroup
{
    param(
        [System.Object]$ManagementGroup,
        [switch]$ExcludeResources,
        [switch]$ExcludeResourceGroups,
        [switch]$ExcludeSubscriptions,
        [string]$ParentPath,
        [switch]$IncludeInheritedRoleAssignments,
        [switch]$IncludeGroupMemberships
    )

    #If no managementgroup has been provided, >
    if($ManagementGroup -eq $NULL)
    {
        #Some functionality is not supported when the context is set to an Office365 subscription. Switch to a supported context
        Switch-AzureInsightSupportedContext

        # > determine the root management group
        $rootManagementGroup = Get-AzManagementGroup
        $ManagementGroup =  Get-AzManagementGroup `
                                -GroupId $rootManagementGroup.name `
                                -Expand `
                                -Recurse

        #if a management group have been found >
        if($ManagementGroup)
        {
            #Set the current path at the root, with the Displayname of the current management group
            $CurrentPath = "/$($ManagementGroup.Displayname)"
        }
        else #if no management group have been found
        {
            #Set the current path at the root
            $CurrentPath = ""
        }

        $Global:AzureInsightFlatResults = @()
    }
    else 
    {
        #Populate the current path based on the parent path and the Displayname of the current management group
        $CurrentPath = "$($ParentPath)/$($ManagementGroup.Displayname)"
    }

    if($ManagementGroup)
    {
        #Temporary
        Write-Verbose "Path: $CurrentPath"

        #Create new object which will contain the details about the managementgroup, the assigned roles and its children
        $ManagementGroupObject = New-Object -TypeName System.Object

        $ManagementGroupObject | Add-Member -MemberType NoteProperty -Name Type -Value $($ManagementGroup.Type)
        $ManagementGroupObject | Add-Member -MemberType NoteProperty -Name DisplayName -Value $($ManagementGroup.DisplayName)

        #Gather the role assignments for this management group
        $ManagementGroupRoleAssignments =   Get-AzureInSightRoleAssignment `
                                            -Scope $ManagementGroup.Id `
                                            -ScopeType "Management Group" `
                                            -AssignmentPath $CurrentPath `
                                            -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                            -IncludeGroupMemberships:$IncludeGroupMemberships

        #Add the gathered role assignments to the RoleAssignments property of the managementgroup object
        $ManagementGroupObject | Add-Member -MemberType NoteProperty -Name RoleAssignments -Value $($ManagementGroupRoleAssignments)

        #Create empty array which will contain the children off this management group
        $ManagementGroupChildResults = @()

        #Cycle through all children of this management group
        Foreach($ManagementGroupChild in $ManagementGroup.Children)
        {
            #determine the type of the child: subscription / managementgroup
            switch ($ManagementGroupChild.Type) 
            {
                "/subscriptions" {
                    #If the ExcludeSubscriptions parameter has not been set, >
                    if($ExcludeSubscriptions -eq $FALSE)
                    {
                        # > Request Subscription details >
                        $Subscription = Get-AZSubscription -SubscriptionId $($ManagementGroupChild.Name)

                        # > Request the data about this child: subscription
                        $ManagementGroupChildResult =   Get-AzureInSightSubscription `
                                                        -Subscription $Subscription `
                                                        -ExcludeResources:$ExcludeResources `
                                                        -ExcludeResourceGroups:$ExcludeResourceGroups `
                                                        -ParentPath $CurrentPath `
                                                        -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                                        -IncludeGroupMemberships:$IncludeGroupMemberships
                    }
                }
                # Request the data about this child: management group
                "/providers/Microsoft.Management/managementGroups" {
                    $ManagementGroupChildResult =   Get-AzureInSightManagementGroup `
                                                        -ManagementGroup $ManagementGroupChild `
                                                        -ExcludeResources:$ExcludeResources `
                                                        -ExcludeResourceGroups:$ExcludeResourceGroups `
                                                        -ExcludeSubscriptions:$ExcludeSubscriptions `
                                                        -ParentPath $CurrentPath `
                                                        -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                                        -IncludeGroupMemberships:$IncludeGroupMemberships
                }            
                Default {}
            }

            #If above switch statement returned any results >
            if($ManagementGroupChildResult)
            {
                #> add them to the array with results of this management groups children
                $ManagementGroupChildResults += $ManagementGroupChildResult

                #Set variable at NULL, to prevent reuse in the next cycle of the loop
                $ManagementGroupChildResult = $NULL
            }
        }

        #If any child results have been returned, >
        if($ManagementGroupChildResults.count -gt 0)
        {
            # > add them to the children property of the managementgroup object
            $ManagementGroupObject | Add-Member -MemberType NoteProperty -Name Children -Value $($ManagementGroupChildResults)
        }

        #return data to caller
        Return $ManagementGroupObject
    }
    elseif($ExcludeSubscriptions -ne $TRUE) #If the ExcludeSubscriptions parameter has not been set, >
    {
        # > request subscriptions
        $Subscriptions = Get-AzSubscription

        #if subscriptions have been returned >
        if($Subscriptions)
        {
            #Create empty array which will contain all the subscriptions
            $SubscriptionResults = @()

            #Cycle through all subscriptions
            Foreach($Subscription in $Subscriptions)
            {
                # Request the data about this subscription >
                $SubscriptionResult =   Get-AzureInSightSubscription `
                                            -Subscription $Subscription `
                                            -ExcludeResources:$ExcludeResources `
                                            -ExcludeResourceGroups:$ExcludeResourceGroups `
                                            -ParentPath $CurrentPath `
                                            -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments

                # > if gathering subscription details returned data >
                if($SubscriptionResult)
                {
                    # > add the subscription details to the array with results of all subscriptions
                    $SubscriptionResults += $SubscriptionResult

                    #Set variable at NULL, to prevent reuse in the next cycle of the loop
                    $SubscriptionResult = $NULL     
                }
            }

            #return data to caller
            Return $SubscriptionResults
        }
    }
}

Function Get-AzureInSightSubscription
{
    param(
        [System.Object]$Subscription,
        [switch]$ExcludeResources,
        [switch]$ExcludeResourceGroups,
        [string]$ParentPath,
        [switch]$IncludeInheritedRoleAssignments,
        [switch]$IncludeGroupMemberships
    )

    write-Verbose "List Subscription: $($Subscription.Name)"

    #Populate the current path based on the parent path and the Displayname of the current subscription
    $CurrentPath = "$($ParentPath)/$($Subscription.Name)"

    #Temporary
    Write-Verbose "Path: $CurrentPath"

    # > to determine if the subscription is in the disabled state
    If($Subscription.State -eq "Disabled")
    {
        Write-Verbose "Filtering the subscription because its disabled"
    }
    elseif($Subscription.SubscriptionPolicies.QuotaId.StartsWith('AAD'))
    {
        Write-Verbose "Filtering the subscription because its used for Office 365"
    }
    else 
    {
        #Create new object which will contain the details about the subscription, the assigned roles and its children
        $SubscriptionObject = New-Object -TypeName System.Object
        $SubscriptionObject | Add-Member -MemberType NoteProperty -Name Type -Value "/subscriptions"
        $SubscriptionObject | Add-Member -MemberType NoteProperty -Name DisplayName -Value $($Subscription.Name)

        #Gather the role assignments for this subscription
        $SubscriptionRoleAssignments =  Get-AzureInSightRoleAssignment `
                                            -Scope "/subscriptions/$($Subscription.id)" `
                                            -ScopeType "Subscription" `
                                            -AssignmentPath $CurrentPath `
                                            -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                            -IncludeGroupMemberships:$IncludeGroupMemberships

        #Add the gathered role assignments to the RoleAssignments property of the subscription object
        $SubscriptionObject | Add-Member -MemberType NoteProperty -Name RoleAssignments -Value $($SubscriptionRoleAssignments )

        #If the ExcludeResourceGroup parameter has not been set, >
        if($ExcludeResourceGroups -eq $FALSE)
        {
            #To gather the resourcegroups of the provided subscription, the context of the current session has to be set
            Set-AzContext -Subscription $($Subscription) | Out-Null

            # > Request the data about this subscription its resourcegroups >
            $ResourceGroupResult =  Get-AzureInSightResourceGroup `
                                        -ExcludeResources:$ExcludeResources `
                                        -ParentPath $CurrentPath `
                                        -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments

            # > if resourcegroups have been returned > 
            if($ResourceGroupResult)
            {
                # > add them to the children property of the subscription object
                $SubscriptionObject | Add-Member -MemberType NoteProperty -Name Children -Value $($ResourceGroupResult)
            }
        
        }
    }
        
    #return data to caller
    Return $SubscriptionObject
}

Function Get-AzureInSightResourceGroup
{
    param(
        [switch]$ExcludeResources,
        [string]$ParentPath,
        [switch]$IncludeInheritedRoleAssignments,
        [switch]$IncludeGroupMemberships
    )

    #List the resource groups
    $ResourceGroups = Get-AzResourceGroup

    # if resourcegroups have been returned
    if($ResourceGroups -ne $NULL)
    {
        #Create empty array which will contain the details of the resource groups
        $ResourceGroupList = @()

        #Cycle through all returned resource groups
        Foreach($ResourceGroup in $ResourceGroups)
        {
            #Temporary
            Write-Verbose "List ResourceGroup: $($ResourceGroup.ResourceGroupName)"

            #Populate the current path based on the parent path and the Displayname of the current resourcegroup
            $CurrentPath = "$($ParentPath)/$($ResourceGroup.ResourceGroupName)"

            #Temporary
            Write-Verbose "Path: $CurrentPath"

            #Create new object which will contain the details about the resource group, the assigned roles and its children
            $ResourceGroupObject = New-Object -TypeName System.Object
            $ResourceGroupObject | Add-Member -MemberType NoteProperty -Name Type -Value "ResourceGroup"
            $ResourceGroupObject | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $($ResourceGroup.ResourceGroupName)

            #Gather the role assignments for this resource group
            $ResourceGroupRoleAssignments =     Get-AzureInSightRoleAssignment `
                                                    -Scope $ResourceGroup.ResourceId `
                                                    -ScopeType "Resource Group" `
                                                    -AssignmentPath $CurrentPath `
                                                    -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                                    -IncludeGroupMemberships:$IncludeGroupMemberships

            #Add the gathered role assignments to the RoleAssignments property of the resource group object
            $ResourceGroupObject | Add-Member -MemberType NoteProperty -Name RoleAssignments -Value $($ResourceGroupRoleAssignments)
            
            #If the ExcludeResources parameter has not been set, >
            if($ExcludeResources -eq $FALSE)
            {
                # > Request the data about this subscription its resources >
                $ResourceResult =   Get-AzureInSightResources `
                                        -ResourceGroup $ResourceGroup `
                                        -ParentPath $CurrentPath `
                                        -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments

                # > if resources have been returned > 
                if($ResourceResult)
                {
                    # > add them to the children property of the resourcegroup object
                    $ResourceGroupObject | Add-Member -MemberType NoteProperty -Name Children -Value $($ResourceResult)
                }
            }

            # add the resourcegroup object to the array with results of all resourcegroups
            $ResourceGroupList += $ResourceGroupObject
        }

    }

    #return data to caller
    Return $ResourceGroupList
}

Function Get-AzureInSightResources
{
    param(
        [System.Object]$ResourceGroup,
        [string]$ParentPath,
        [switch]$IncludeInheritedRoleAssignments,
        [switch]$IncludeGroupMemberships
    )

    #List the resources
    $Resources = Get-AzResource -ResourceGroupName $ResourceGroup.ResourceGroupName

    #if resourcegroups have been returned
    if($Resources -ne $NULL)
    {
        #Create empty array which will contain the details of the resources
        $ResourceList = @()

        #Cycle through all returned resources
        Foreach($Resource in $Resources)
        {
            #temporary
            Write-Verbose "List Resource: $($Resource.Name)"

            #Populate the current path based on the parent path and the Displayname of the current resource
            $CurrentPath = "$($ParentPath)/$($Resource.Name)"

            #Temporary
            Write-Verbose "Path: $CurrentPath"

            #Create new object which will contain the details about the resource and the assigned roles
            $ResourceObject = New-Object -TypeName System.Object
            $ResourceObject | Add-Member -MemberType NoteProperty -Name Type -Value $($Resource.ResourceType)
            $ResourceObject | Add-Member -MemberType NoteProperty -Name Name -Value $($Resource.Name)

            #Gather the role assignments for this resource
            $ResourceRoleAssignments =  Get-AzureInSightRoleAssignment `
                                            -Scope $Resource.ResourceId `
                                            -ScopeType "Resource" `
                                            -AssignmentPath $CurrentPath `
                                            -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
                                            -IncludeGroupMemberships:$IncludeGroupMemberships

            #Add the gathered role assignments to the RoleAssignments property of the resources object
            $ResourceObject | Add-Member -MemberType NoteProperty -Name RoleAssignments -Value $($ResourceRoleAssignments)
            
            # add the resource object to the array with results of all resources
            $ResourceList += $ResourceObject
        }

    }

    #return data to caller
    Return $ResourceList
}

Function Get-AzureInSightRoleAssignment
{
    param(
        [string]$Scope,
        [string]$ScopeType,
        [string]$AssignmentPath,
        [switch]$IncludeInheritedRoleAssignments,
        [switch]$IncludeGroupMemberships
    )

    Write-Verbose "Get Role Assignments for scope $($Scope)"

    #Request the role assignments for this scope
    $RoleAssignments = Get-AzRoleAssignment -Scope $Scope

    #if role assignments have been returned >
    if($RoleAssignments)
    {
        # > Create empty array which will contain the details of the role assignments
        $RoleAssignmentList = @()

        #Cycle through all returned role assignments
        foreach($RoleAssignment in $RoleAssignments )
        {
            #if the assignments scope is equal to the current scope (permissions are not inherited) ór they're not equal but the IncludeInheritedRoleAssignments is set >
            if(($RoleAssignment.Scope -eq $Scope) -or (($RoleAssignment.Scope -ne $Scope) -and $IncludeInheritedRoleAssignments -eq $TRUE))
            {
                #Determine if the objecttype is Unknown (removed identity)
                if($($RoleAssignment.ObjectType) -eq "Unknown")
                {
                    Write-Verbose "Skipping Identity with ObjectID $($RoleAssignment.ObjectId) because the type is unknown"

                    $IdentityResult = New-Object -TypeName System.Object
                    $IdentityResult | Add-Member -MemberType NoteProperty -Name Displayname -Value "Identity not found"
                }
                elseif($RoleAssignment.Displayname.StartsWith("Foreign Principal")) #Foreign principals can't be distinquised by the object type
                {
                    $IdentityResult = $RoleAssignment
                }
                elseif($($RoleAssignment.ObjectType) -eq "User")
                {
                    #Get User details
                    $IdentityResult =   Get-AzureInSightUserDetails `
                                            -ObjectId $RoleAssignment.ObjectId
                }
                elseif($($RoleAssignment.ObjectType) -eq "ServicePrincipal")
                {
                    #Get Service Principal details
                    $IdentityResult =   Get-AzureInSightServicePrincipalDetails `
                                            -ObjectId $RoleAssignment.ObjectId
                }
                elseif($($RoleAssignment.ObjectType) -eq "Group")
                {
                    #Get Group Details and members
                    $IdentityResult =   Get-AzureInSightGroupDetails `
                                            -ObjectId $RoleAssignment.ObjectId `
                                            -IncludeGroupMemberships:$IncludeGroupMemberships
                }

                #Get Details about the role within the role assignment
                $RoleResult =   Get-AzureInSightRoleDetails `
                                    -DefinitionID $RoleAssignment.RoleDefinitionId

                #Create new object which will contain the details (flat structure) about the role assignment
                $RoleAssignmentObject = New-Object -TypeName System.Object
                $RoleAssignmentObject | Add-Member -MemberType NoteProperty -Name Identity -Value $IdentityResult
                $RoleAssignmentObject | Add-Member -MemberType NoteProperty -Name Role -Value $RoleResult

                #Create new object which will contain the details (hierarchical structure) about the role assignment
                $RoleAssignmentFlatObject = New-Object -TypeName System.Object
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name Scope -Value $AssignmentPath
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name ScopeType -Value $ScopeType
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name Identity -Value $IdentityResult.Displayname
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name 'IdentityType' -Value $IdentityResult.ObjectType
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name RoleDefinition -Value $RoleResult.Name

                #if the assignments scope is equal to the current scope, permissions are not inherited
                if($RoleAssignment.Scope -eq $Scope)
                {
                    #set inheritance to FALSE
                    $Inherited = $FALSE
                }
                else 
                {
                    #set inheritance to TRUE
                    $Inherited = $TRUE
                }

                #add the inheritance state to the role assignments objects
                $RoleAssignmentObject | Add-Member -MemberType NoteProperty -Name Inherited -Value $Inherited
                $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name Inherited -Value $Inherited

                #The assignments is made directly on the identity (group memberships are handled below). Set Assignment property to 'direct'
                $RoleAssignmentFlatObject| Add-Member -MemberType NoteProperty -Name Assignment -Value "Direct"

                # add the role assignment object to the array with results of all role assignments
                $RoleAssignmentList += $RoleAssignmentObject

                # add the role assignment object to the array with the (flat structure) results of all role assignments
                $Global:AzureInsightFlatResults += $RoleAssignmentFlatObject

                #if the identity of the current role assignments contains members and the IncludeGroupMemberships is set >
                if($IdentityResult.GroupMembers -ne $NULL -and $IncludeGroupMemberships -eq $TRUE)
                {
                    # > initiate the creation of objects for the flat permissions overview
                    Add-AzureInSightGroupMembersFlatResult `
                        -Identity $IdentityResult `
                        -Scope $AssignmentPath `
                        -ScopeType $ScopeType `
                        -Inherited:$Inherited `
                        -Role $RoleResult
                }
            }
            else 
            {
            }
        }
    }

    #return data to caller
    return $RoleAssignmentList
}

Function Add-AzureInSightGroupMembersFlatResult
{
    param(
        [System.Object]$Identity,
        [string]$Scope,
        [string]$ScopeType,
        [switch]$Inherited,
        [System.Object]$Role
    )

    #Cycle through all group members
    Foreach($GroupMember in $Identity.GroupMembers)
    {
        #Create new object which will contain the details (flat structure) about the role assignment of the group member
        $RoleAssignmentFlatObject = New-Object -TypeName System.Object
        $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name Scope -Value $Scope
        $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name ScopeType -Value $ScopeType
        $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name Identity -Value $GroupMember.Displayname
        $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name 'IdentityType' -Value $GroupMember.ObjectType
        $RoleAssignmentFlatObject | Add-Member -MemberType NoteProperty -Name RoleDefinition -Value $Role.Name
        $RoleAssignmentFlatObject| Add-Member -MemberType NoteProperty -Name Inherited -Value $Inherited

        #The assignments is inherited by a group membership. Set assignment property to the inheritance path 
        $RoleAssignmentFlatObject| Add-Member -MemberType NoteProperty -Name Assignment -Value "Group membership of '$($Identity.Displayname)'"

        #if this groupmember does contain child memberships >
        if($GroupMember.GroupMembers -ne $NULL)
        {
            # > initiate the creation of objects for the flat permissions overview by calling this function itself
            Add-AzureInSightGroupMembersFlatResult `
                -Identity $GroupMember `
                -Scope $Scope `
                -Inherited:$Inherited `
                -Role $Role
        }

        # add the role assignment object to the array with the (flat structure) results of all role assignments
        $Global:AzureInsightFlatResults += $RoleAssignmentFlatObject
    }
}

Function Get-AzureInSightGroupDetails
{
    param(
        [string]$ObjectId,
        [switch]$IncludeGroupMemberships
    )

    #temporary
    Write-Verbose "List Group details with ObjectID $($ObjectID)"

    #List the group
    $GroupObject = Get-AzADGroup -ObjectId $ObjectId

    #If the IncludeGroupMemberships parameter has been set, >
    if($IncludeGroupMemberships -eq $TRUE)
    {
        # > request group members
        $GroupMembers = Get-AzADGroupMember -ObjectId $ObjectId

        #Create empty array which will contain the details of the group members
        $GroupMemberResults = @()

        #if gathering group members returned members >
        if($GroupMembers)
        {
            #Cycle through all returned group members
            Foreach($GroupMember in $GroupMembers)
            {
                #determine the type of the group member: user / service principal / group
                switch ($GroupMember.ObjectType) {
                    # Request the data about this group member: user
                    "User" 
                    { 
                        $GroupMemberResult = Get-AzureInSightUserDetails -ObjectId $GroupMember.ID 
                    }
                    # Request the data about this group member: Service Principal
                    "ServicePrincipal" 
                    { 
                        $GroupMemberResult = Get-AzureInSightServicePrincipalDetails -ObjectId $GroupMember.ID 
                    }
                    # Request the data about this group member: Group
                    "Group" 
                    { 
                        $GroupMemberResult = Get-AzureInSightGroupDetails -ObjectId $GroupMember.Id -IncludeGroupMemberships:$IncludeGroupMemberships
                    }
                    Default 
                    {
                        Write-Error "Unknown Groupmember Type: $($GroupMember.Type)"
                    }
                }

                # add the group member to the array with details of all group members
                $GroupMemberResults += $GroupMemberResult
            }
        }

        #Add the gathered group members to the Group Members property of the group object
        $GroupObject  | Add-Member -MemberType NoteProperty -Name GroupMembers -Value $GroupMemberResults
    }

    #return data to caller
    Return $GroupObject  
}
Function Get-AzureInSightServicePrincipalDetails
{
    param(
        [string]$ObjectId
    )

    Write-Verbose "List Service Principal with ObjectID $($ObjectID)"

    $ServicePrincipalObject = Get-AzADServicePrincipal -ObjectId $ObjectId

    #Todo: Add Additional Information to ServicePrincipalObject

    return $ServicePrincipalObject
}

Function Get-AzureInSightUserDetails
{
    param(
        [string]$ObjectId
    )

    Write-Verbose "List User with ObjectID $($ObjectID)"

    $UserObject = Get-AzADUser -ObjectId $ObjectId

    #Todo: Add Additional Information to UserObject

    Return $UserObject
}

Function Get-AzureInSightRoleDetails
{
    param(
        [string]$DefinitionID
    )

    Write-Verbose "List Role with DefinitionID $($DefinitionID)"

    $RoleObject = Get-AzRoleDefinition -Id $DefinitionID

    #Todo: Add Additional Information to RoleObject

    Return $RoleObject
}

#Load modules
Import-AzureInSightModules

#Connect
Connect-AzureInsight

#Request permissions
Get-AzureInSightPermissions `
    -ExcludeResources:$ExcludeResources `
    -ExcludeResourceGroups:$ExcludeResourceGroups `
    -ExcludeSubscriptions:$ExcludeSubscriptions `
    -IncludeInheritedRoleAssignments:$IncludeInheritedRoleAssignments `
    -IncludeGroupMemberships:$IncludeGroupMemberships `
    -Mode:"AzureRBAC" `
    -OutputPath $OutputPath `
    -Verbose

#Cleanup
Remove-AzureInSightVariables

