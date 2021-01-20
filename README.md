## Azure RBAC permission insight

Creates an overview of the existing role assignments within Azure RBAC. Can be extremely usefull to determine who has access at which scope and what permissions

- Queries the role assignments on different Azure RBAC levels:
  - Management Groups
  - Subscriptions
  - Resource Groups
  - Resources
- Shows details about permission inheritance from parent to child levels
- Provides insight in permissions aquired by means of group memberships
- Exports the results in both a hierarchical (JSON) and flat structure (CSV). The former does provide the most detailed information.

### Requirements:
The following PowerShell modules are required and will be installed automatically:
- Az.Accounts
- Az.Resources

In order to retrieve all the information from Azure RBAC you'll need an account that has permissions to request the role assignments:
- In case you're using management groups: On the root management groups.
- If not: On the subscriptions.

On the Azure AD level you need to have permissions to list the details of identities.

### Usage:

No parameters specified: _A folder will be created automatically in the current directory with the date and time (YYYYDDMMTHHMM) as name . Modern authentication will prompt for authentication information._
```
.\AzurePermissionInsight.ps1
```
`-ExcludeResources` Parameter:
_[OPTIONAL] When using this parameter, all resources will be skipped._
```
.\AzurePermissionInsight.ps1 -ExcludeResources
```
`-ExcludeResourceGroups` Parameter:
_[OPTIONAL] When using this parameter, all resource groups and children (e.g. resources) will be skipped. So the ExcludeResources parameter is not interpreted when this parameter is used._
```
.\AzurePermissionInsight.ps1 -ExcludeResourceGroups
```
`-ExcludeSubscriptions` Parameter:
_[OPTIONAL] When using this parameter, all subscriptions and children (e.g. resource groups and resources) will be skipped. So the ExcludeResourceGroups and ExcludeResources parameters are not interpreted when this parameter is used._
```
.\AzurePermissionInsight.ps1 -ExcludeSubscriptions
```
`-IncludeInheritedRoleAssignments` Parameter:
_[OPTIONAL] Within Azure RBAC permissions will be propagated to child objects (Management Group -> Subscription > Resource Group > Resources). Setting this parameter will include inherited permissions within the results._
```
.\AzurePermissionInsight.ps1 -IncludeInheritedRoleAssignments
```

`-IncludeGroupMemberships` Parameter:
_[OPTIONAL] When roles are assigned to a group, the role assignment is also applicable to all members of the group. Setting this parameter will include these group memberships within the results._
```
.\AzurePermissionInsight.ps1 -IncludeGroupMemberships
```

`-OutputPath` Parameter:
_[OPTIONAL] The output of the script is saved in the current directoy, unless another location has been provided using this parameter._
```
.\AzurePermissionInsight.ps1 -OutputPath "C:\Temp"
```

### Output:
This script will save the results in the current directory, unless another path has been provided in the OutputPath parameter.
-  `.JSON` format, which contains the resource and groupmembership hierarchy. This file does contain the most details.
- `.CSV` format, containing a flat structure

#### Example - Flat table

|Scope|ScopeType|Identity|IdentityType|RoleDefinition|Inherited|Assignment|
|--|--|--|--|--|--|--|
|/Tenant Root Group|Management Group|SPN01|ServicePrincipal|User Access Administrator|FALSE|Direct|
|/Tenant Root Group|Management Group|User01|User|Owner|FALSE|Direct|
|/Tenant Root Group|Management Group|Group01|Group|Reader|FALSE|Direct|
|/Tenant Root Group|Management Group|User01|User|Reader|FALSE|Group membership of 'Group01'|
|/Tenant Root Group/Child Management Group|Management Group|SPN01|ServicePrincipal|User Access Administrator|FALSE|Direct|
|/Tenant Root Group/Child Management Group|Management Group|SPN01|ServicePrincipal|User Access Administrator|TRUE|Direct|
|/Tenant Root Group/Child Management Group|Management Group|User01|User|Owner|TRUE|Direct|
|/Tenant Root Group/Child Management Group|Management Group|Group01|Group|Reader|TRUE|Direct|
|/Tenant Root Group/Child Management Group|Management Group|User01|User|Reader|TRUE|Group membership of 'Group01'|
|/Tenant Root Group/Child Management Group/Subscription001|Subscription|SPN01|ServicePrincipal|User Access Administrator|FALSE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001|Subscription|SPN01|ServicePrincipal|User Access Administrator|TRUE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001|Subscription|User01|User|Owner|TRUE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001|Subscription|Group01|Group|Reader|TRUE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001|Subscription|User01|User|Reader|TRUE|Group membership of 'Group01'|
|/Tenant Root Group/Child Management Group/Subscription001/ResourceGroup001|Resource Group|SPN01|ServicePrincipal|User Access Administrator|TRUE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001/ResourceGroup001|Resource Group|User01|User|Owner|TRUE|Direct|
|/Tenant Root Group/Child Management Group/Subscription001/ResourceGroup001|Resource Group|Group01|Group|Reader|TRUE|Direct|

#### Example - Hierarchy

```
{
    "Type": "/providers/Microsoft.Management/managementGroups",
    "DisplayName": "Tenant Root Group",
    "RoleAssignments": [
        {
            "Identity": {
                "ServicePrincipalNames": [
                    "**********"
                ],
                "ApplicationId": "**********",
                "ObjectType": "ServicePrincipal",
                "DisplayName": "SPN01",
                "Id": "**********",
                "Type": null
            },
            "Role": {
                "Name": "User Access Administrator",
                "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                "IsCustom": false,
                "Description": "Lets you manage user access to Azure resources.",
                "Actions": [
                    "*/read",
                    "Microsoft.Authorization/*",
                    "Microsoft.Support/*"
                ],
                "NotActions": [],
                "DataActions": [],
                "NotDataActions": [],
                "AssignableScopes": [
                    "/"
                ]
            },
            "Inherited": false
        },
        {
            "Identity": {
                "UserPrincipalName": "**********",
                "ObjectType": "User",
                "UsageLocation": "**********",
                "GivenName": "**********",
                "Surname": "**********",
                "AccountEnabled": true,
                "MailNickname": "**********",
                "Mail": "**********",
                "DisplayName": "User01",
                "Id": "**********",
                "Type": "Member"
            },
            "Role": {
                "Name": "Owner",
                "Id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "IsCustom": false,
                "Description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
                "Actions": [
                    "*"
                ],
                "NotActions": [],
                "DataActions": [],
                "NotDataActions": [],
                "AssignableScopes": [
                    "/"
                ]
            },
            "Inherited": false
        },
        {
            "Identity": {
                "SecurityEnabled": true,
                "MailNickname": "**********",
                "ObjectType": "Group",
                "Description": null,
                "DisplayName": "Group01",
                "Id": "**********",
                "Type": "Group",
                "GroupMembers": [
                    {
                        "UserPrincipalName": "**********",
                        "ObjectType": "User",
                        "UsageLocation": "**********",
                        "GivenName": "**********",
                        "Surname": "**********",
                        "AccountEnabled": true,
                        "MailNickname": "**********",
                        "Mail": "**********",
                        "DisplayName": "User01",
                        "Id": "**********",
                        "Type": "Member"
                    }
                ]
            },
            "Role": {
                "Name": "Reader",
                "Id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                "IsCustom": false,
                "Description": "View all resources, but does not allow you to make any changes.",
                "Actions": [
                    "*/read"
                ],
                "NotActions": [],
                "DataActions": [],
                "NotDataActions": [],
                "AssignableScopes": [
                    "/"
                ]
            },
            "Inherited": false
        }
    ],
    "Children": [
        {
            "Type": "/providers/Microsoft.Management/managementGroups",
            "DisplayName": "Child Management Group",
            "RoleAssignments": [
                {
                    "Identity": {
                        "ServicePrincipalNames": [
                            "**********"
                        ],
                        "ApplicationId": "**********",
                        "ObjectType": "ServicePrincipal",
                        "DisplayName": "SPN01",
                        "Id": "**********",
                        "Type": null
                    },
                    "Role": {
                        "Name": "User Access Administrator",
                        "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                        "IsCustom": false,
                        "Description": "Lets you manage user access to Azure resources.",
                        "Actions": [
                            "*/read",
                            "Microsoft.Authorization/*",
                            "Microsoft.Support/*"
                        ],
                        "NotActions": [],
                        "DataActions": [],
                        "NotDataActions": [],
                        "AssignableScopes": [
                            "/"
                        ]
                    },
                    "Inherited": false
                },
                {
                    "Identity": {
                        "ServicePrincipalNames": [
                            "**********"
                        ],
                        "ApplicationId": "**********",
                        "ObjectType": "ServicePrincipal",
                        "DisplayName": "SPN01",
                        "Id": "**********",
                        "Type": null
                    },
                    "Role": {
                        "Name": "User Access Administrator",
                        "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                        "IsCustom": false,
                        "Description": "Lets you manage user access to Azure resources.",
                        "Actions": [
                            "*/read",
                            "Microsoft.Authorization/*",
                            "Microsoft.Support/*"
                        ],
                        "NotActions": [],
                        "DataActions": [],
                        "NotDataActions": [],
                        "AssignableScopes": [
                            "/"
                        ]
                    },
                    "Inherited": true
                },
                {
                    "Identity": {
                        "UserPrincipalName": "**********",
                        "ObjectType": "User",
                        "UsageLocation": "**********",
                        "GivenName": "**********",
                        "Surname": "**********",
                        "AccountEnabled": true,
                        "MailNickname": "**********",
                        "Mail": "**********",
                        "DisplayName": "User01",
                        "Id": "**********",
                        "Type": "Member"
                    },
                    "Role": {
                        "Name": "Owner",
                        "Id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                        "IsCustom": false,
                        "Description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
                        "Actions": [
                            "*"
                        ],
                        "NotActions": [],
                        "DataActions": [],
                        "NotDataActions": [],
                        "AssignableScopes": [
                            "/"
                        ]
                    },
                    "Inherited": true
                },
                {
                    "Identity": {
                        "SecurityEnabled": true,
                        "MailNickname": "e3ee89b1-0",
                        "ObjectType": "Group",
                        "Description": null,
                        "DisplayName": "Group01",
                        "Id": "**********",
                        "Type": "Group",
                        "GroupMembers": [
                            {
                                "UserPrincipalName": "**********",
                                "ObjectType": "User",
                                "UsageLocation": "**********",
                                "GivenName": "**********",
                                "Surname": "**********",
                                "AccountEnabled": true,
                                "MailNickname": "**********",
                                "Mail": "**********",
                                "DisplayName": "User01",
                                "Id": "**********",
                                "Type": "Member"
                            }
                        ]
                    },
                    "Role": {
                        "Name": "Reader",
                        "Id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                        "IsCustom": false,
                        "Description": "View all resources, but does not allow you to make any changes.",
                        "Actions": [
                            "*/read"
                        ],
                        "NotActions": [],
                        "DataActions": [],
                        "NotDataActions": [],
                        "AssignableScopes": [
                            "/"
                        ]
                    },
                    "Inherited": true
                }
            ],
            "Children": {
                "Type": "/subscriptions",
                "DisplayName": "Subscription001",
                "RoleAssignments": [
                    {
                        "Identity": {
                            "ServicePrincipalNames": [
                                "**********"
                            ],
                            "ApplicationId": "**********",
                            "ObjectType": "ServicePrincipal",
                            "DisplayName": "SPN01",
                            "Id": "**********",
                            "Type": null
                        },
                        "Role": {
                            "Name": "User Access Administrator",
                            "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                            "IsCustom": false,
                            "Description": "Lets you manage user access to Azure resources.",
                            "Actions": [
                                "*/read",
                                "Microsoft.Authorization/*",
                                "Microsoft.Support/*"
                            ],
                            "NotActions": [],
                            "DataActions": [],
                            "NotDataActions": [],
                            "AssignableScopes": [
                                "/"
                            ]
                        },
                        "Inherited": false
                    },
                    {
                        "Identity": {
                            "ServicePrincipalNames": [
                                "**********"
                            ],
                            "ApplicationId": "**********",
                            "ObjectType": "ServicePrincipal",
                            "DisplayName": "SPN01",
                            "Id": "**********",
                            "Type": null
                        },
                        "Role": {
                            "Name": "User Access Administrator",
                            "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                            "IsCustom": false,
                            "Description": "Lets you manage user access to Azure resources.",
                            "Actions": [
                                "*/read",
                                "Microsoft.Authorization/*",
                                "Microsoft.Support/*"
                            ],
                            "NotActions": [],
                            "DataActions": [],
                            "NotDataActions": [],
                            "AssignableScopes": [
                                "/"
                            ]
                        },
                        "Inherited": true
                    },
                    {
                        "Identity": {
                            "ServicePrincipalNames": [
                                "**********"
                            ],
                            "ApplicationId": "**********",
                            "ObjectType": "ServicePrincipal",
                            "DisplayName": "SPN01",
                            "Id": "**********",
                            "Type": null
                        },
                        "Role": {
                            "Name": "User Access Administrator",
                            "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                            "IsCustom": false,
                            "Description": "Lets you manage user access to Azure resources.",
                            "Actions": [
                                "*/read",
                                "Microsoft.Authorization/*",
                                "Microsoft.Support/*"
                            ],
                            "NotActions": [],
                            "DataActions": [],
                            "NotDataActions": [],
                            "AssignableScopes": [
                                "/"
                            ]
                        },
                        "Inherited": true
                    },
                    {
                        "Identity": {
                            "UserPrincipalName": "**********",
                            "ObjectType": "User",
                            "UsageLocation": "**********",
                            "GivenName": "**********",
                            "Surname": "**********",
                            "AccountEnabled": true,
                            "MailNickname": "**********",
                            "Mail": "**********",
                            "DisplayName": "User01",
                            "Id": "**********",
                            "Type": "Member"
                        },
                        "Role": {
                            "Name": "Owner",
                            "Id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                            "IsCustom": false,
                            "Description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
                            "Actions": [
                                "*"
                            ],
                            "NotActions": [],
                            "DataActions": [],
                            "NotDataActions": [],
                            "AssignableScopes": [
                                "/"
                            ]
                        },
                        "Inherited": true
                    },
                    {
                        "Identity": {
                            "SecurityEnabled": true,
                            "MailNickname": "**********",
                            "ObjectType": "Group",
                            "Description": null,
                            "DisplayName": "Group01",
                            "Id": "**********",
                            "Type": "Group",
                            "GroupMembers": [
                                {
                                    "UserPrincipalName": "**********",
                                    "ObjectType": "**********",
                                    "UsageLocation": "**********",
                                    "GivenName": "**********",
                                    "Surname": "**********",
                                    "AccountEnabled": true,
                                    "MailNickname": "**********",
                                    "Mail": "**********",
                                    "DisplayName": "User01",
                                    "Id": "**********",
                                    "Type": "Member"
                                }
                            ]
                        },
                        "Role": {
                            "Name": "Reader",
                            "Id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                            "IsCustom": false,
                            "Description": "View all resources, but does not allow you to make any changes.",
                            "Actions": [
                                "*/read"
                            ],
                            "NotActions": [],
                            "DataActions": [],
                            "NotDataActions": [],
                            "AssignableScopes": [
                                "/"
                            ]
                        },
                        "Inherited": true
                    }
                ],
                "Children": [
                    {
                        "Type": "ResourceGroup",
                        "ResourceGroupName": "ResourceGroup001",
                        "RoleAssignments": [
                            {
                                "Identity": {
                                    "ServicePrincipalNames": [
                                        "**********"
                                    ],
                                    "ApplicationId": "**********",
                                    "ObjectType": "ServicePrincipal",
                                    "DisplayName": "SPN01",
                                    "Id": "**********",
                                    "Type": null
                                },
                                "Role": {
                                    "Name": "User Access Administrator",
                                    "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                                    "IsCustom": false,
                                    "Description": "Lets you manage user access to Azure resources.",
                                    "Actions": [
                                        "*/read",
                                        "Microsoft.Authorization/*",
                                        "Microsoft.Support/*"
                                    ],
                                    "NotActions": [],
                                    "DataActions": [],
                                    "NotDataActions": [],
                                    "AssignableScopes": [
                                        "/"
                                    ]
                                },
                                "Inherited": true
                            },
                            {
                                "Identity": {
                                    "ServicePrincipalNames": [
                                        "**********"
                                    ],
                                    "ApplicationId": "**********",
                                    "ObjectType": "ServicePrincipal",
                                    "DisplayName": "SPN01",
                                    "Id": "**********",
                                    "Type": null
                                },
                                "Role": {
                                    "Name": "User Access Administrator",
                                    "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                                    "IsCustom": false,
                                    "Description": "Lets you manage user access to Azure resources.",
                                    "Actions": [
                                        "*/read",
                                        "Microsoft.Authorization/*",
                                        "Microsoft.Support/*"
                                    ],
                                    "NotActions": [],
                                    "DataActions": [],
                                    "NotDataActions": [],
                                    "AssignableScopes": [
                                        "/"
                                    ]
                                },
                                "Inherited": true
                            },
                            {
                                "Identity": {
                                    "ServicePrincipalNames": [
                                        "**********"
                                    ],
                                    "ApplicationId": "**********",
                                    ,
                                    "ObjectType": "ServicePrincipal",
                                    "DisplayName": "SPN01",
                                    "Id": "**********",
                                    "Type": null
                                },
                                "Role": {
                                    "Name": "User Access Administrator",
                                    "Id": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                                    "IsCustom": false,
                                    "Description": "Lets you manage user access to Azure resources.",
                                    "Actions": [
                                        "*/read",
                                        "Microsoft.Authorization/*",
                                        "Microsoft.Support/*"
                                    ],
                                    "NotActions": [],
                                    "DataActions": [],
                                    "NotDataActions": [],
                                    "AssignableScopes": [
                                        "/"
                                    ]
                                },
                                "Inherited": true
                            },
                            {
                                "Identity": {
                                    "UserPrincipalName": "**********",
                                    "ObjectType": "User",
                                    "UsageLocation": "**********",
                                    "GivenName": "**********",
                                    "Surname": "**********",
                                    "AccountEnabled": true,
                                    "MailNickname": "**********",
                                    "Mail": "**********",
                                    "DisplayName": "User01",
                                    "Id": "**********",
                                    "Type": "Member"
                                },
                                "Role": {
                                    "Name": "Owner",
                                    "Id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                                    "IsCustom": false,
                                    "Description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
                                    "Actions": [
                                        "*"
                                    ],
                                    "NotActions": [],
                                    "DataActions": [],
                                    "NotDataActions": [],
                                    "AssignableScopes": [
                                        "/"
                                    ]
                                },
                                "Inherited": true
                            },
                            {
                                "Identity": {
                                    "SecurityEnabled": true,
                                    "MailNickname": "**********",
                                    "ObjectType": "Group",
                                    "Description": null,
                                    "DisplayName": "Group01",
                                    "Id": "**********",
                                    "Type": "Group"
                                },
                                "Role": {
                                    "Name": "Reader",
                                    "Id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                                    "IsCustom": false,
                                    "Description": "View all resources, but does not allow you to make any changes.",
                                    "Actions": [
                                        "*/read"
                                    ],
                                    "NotActions": [],
                                    "DataActions": [],
                                    "NotDataActions": [],
                                    "AssignableScopes": [
                                        "/"
                                    ]
                                },
                                "Inherited": true
                            }
                        ]
                    }
                ]
            }
        }
    ]
}
```

### Contribute

When you found a bug, please report a new issue or contribute to an existing one.

If you have suggestions for this script, you can contact me using: info@seb8iaan.com


