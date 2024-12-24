#Send email with attachment from app registration
$MailClientId = ""
$MailClientSecret = ""
$MailSender = "rubicon-monitor@<tenantname>.onmicrosoft.com"
$MailTo = "support@rubicon.nl"

#Connect to PnP Online
$ClientId = ""
$TenantId = ""
$Thumbprint = ""

Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $Thumbprint

$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

# Set the inactivity threshold
$DaysInactive = 45
$time = (Get-Date).Adddays(-($DaysInactive))

# Define the NewUserThresholdDate parameter
$NewUserThresholdDate = (Get-Date).AddDays(-30) # Example: exclude users created in the last 90 days

# Define the properties we want to retrieve
$Properties = 'Id,DisplayName,Mail,UserPrincipalName,UserType,AccountEnabled,SignInActivity,CreatedDateTime'

Write-Host "Get Inactive Users $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Get all inactive users
$InactiveUsers = Get-MgUser -All -Property $Properties | 
    Where-Object {
        ($_.SignInActivity.LastSignInDateTime -lt $time -or $null -eq $_.SignInActivity.LastSignInDateTime) -and 
        $_.AccountEnabled -eq $True -and
        $_.CreatedDateTime -lt $NewUserThresholdDate
    } | ForEach-Object {
    $LastSuccessfulSignInDate = if ($_.SignInActivity.LastSignInDateTime) {
        $_.SignInActivity.LastSignInDateTime
    } else {
        "Never Signed-in"
    }

    $DaysSinceLastSignIn = if ($_.SignInActivity.LastSignInDateTime) {
        (New-TimeSpan -Start $_.SignInActivity.LastSignInDateTime -End (Get-Date)).Days
    } else {
        "N/A"
    }

    [PSCustomObject]@{
        UserPrincipalName        = $_.UserPrincipalName
        DisplayName              = $_.DisplayName
        UserType                 = $_.UserType
        AccountEnabled           = $_.AccountEnabled
        LastSuccessfulSignInDate = $LastSuccessfulSignInDate
        DaysSinceLastSignIn      = $DaysSinceLastSignIn
        CreatedDateTime          = $_.CreatedDateTime
    }
}

# Disable inactive users
# foreach ($InactiveUser in $InactiveUsers) {
#    try {
#        Update-MgUser -UserId $InactiveUser.Id -AccountEnabled:$false
#        Write-Host "Disabled user: $($InactiveUser.UserPrincipalName)"
#    } catch {
#        Write-Host "Failed to disable user: $($InactiveUser.UserPrincipalName). Error: $($_.Exception.Message)"
#    }
#}


# Generate HTML report as a string
$htmlReport = $InactiveUsers | ConvertTo-Html -Head $CSSStyle | Out-String

#Connect to GRAPH API
$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $MailClientId
    Client_Secret = $MailClientSecret

}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

# Prepare email body
$emailBody = @"
<h2>Inactive Users Report</h2>
<p>This email reports on user accounts that have been inactive for 45 days or more. These accounts have been automatically disabled.</p>
<p>Report generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
$htmlReport
"@

# Modify the email sending part
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
{
    "message": {
        "subject": "Inactive User Accounts Disabled - M365",
        "body": {
            "contentType": "HTML",
            "content": "$($emailBody -replace '"','\"')"
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "$MailTo"
                }
            }
        ]
    },
    "saveToSentItems": "false"
}
"@

# Send the email
Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend