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


# Get all devices
$Devices = Get-MgDevice -All

# Filter inactive devices
$InactiveDevices = $Devices | Where-Object {
    ($_.ApproximateLastSignInDateTime -lt $time -or $null -eq $_.ApproximateLastSignInDateTime) -and 
    $_.AccountEnabled -eq $True
} | ForEach-Object {
    $LastSignInDate = if ($_.ApproximateLastSignInDateTime) {
        $_.ApproximateLastSignInDateTime
    } else {
        "Never Signed-in"
    }

    $DaysSinceLastSignIn = if ($_.ApproximateLastSignInDateTime) {
        (New-TimeSpan -Start $_.ApproximateLastSignInDateTime -End (Get-Date)).Days
    } else {
        "N/A"
    }

    [PSCustomObject]@{
        # Id                    = $_.Id
        DisplayName           = $_.DisplayName
        # DeviceId              = $_.DeviceId
        OperatingSystem       = $_.OperatingSystem
        OperatingSystemVersion = $_.OperatingSystemVersion
        AccountEnabled        = $_.AccountEnabled
        LastSignInDate        = $LastSignInDate
        DaysSinceLastSignIn   = $DaysSinceLastSignIn
        EnrollmentType        = $_.EnrollmentType
        ManagementType        = $_.ManagementType
    }
}

# Disable inactive devices
# foreach ($InactiveDevice in $InactiveDevices) {
#     try {
#         Update-MgDevice -DeviceId $InactiveDevice.Id -AccountEnabled:$false
#         Write-Host "Disabled device: $($InactiveDevice.DisplayName)"
#     } catch {
#         Write-Host "Failed to disable device: $($InactiveDevice.DisplayName). Error: $($_.Exception.Message)"
#     }
# }

# Generate HTML report as a string
$htmlReport = $InactiveDevices | ConvertTo-Html -Head $CSSStyle | Out-String

#Connect to GRAPH API
$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $MailClientId
    Client_Secret = $MailClientSecret

}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

# Prepare email body
$emailBody = @"
<h2>Microsoft 365 Report | Inactive Devices [$($InactiveDevices.Count)]</h2>
<p>This email reports on devices that have been inactive for 45 days or more. These devices have been automatically disabled.</p>
<p>Report generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
$htmlReport
"@

# Modify the email sending part
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
{
    "message": {
        "subject": "Microsoft 365 Report | Inactive Devices [$($InactiveDevices.Count)]",
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