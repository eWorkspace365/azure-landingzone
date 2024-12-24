# Azure AD Application details
$ClientId = ""
$TenantId = ""
$Thumbprint = ""

# Import required modules
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Devices.CorporateManagement -Scope CurrentUser

# Import the modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Devices.CorporateManagement
Import-Module Microsoft.Graph.Identity.DirectoryManagement

# Authenticate to Microsoft Graph


# Set the date threshold (45 days ago)
$thresholdDate = (Get-Date).AddDays(-45).ToString("yyyy-MM-dd")

# Fetch inactive devices
$inactiveDevices = Get-MgDevice -All -Filter "approximateLastSignInDateTime le $thresholdDate"

# Output the results
$inactiveDevices | Select-Object DisplayName, DeviceId, ApproximateLastSignInDateTime | Format-Table -AutoSize

# Disconnect from Microsoft Graph


# Generate HTML report as a string
$htmlReport = $InactiveDevices | ConvertTo-Html -Head $CSSStyle | Out-String

#Send email with attachment from app registration
$MailClientID = ""
$MailclientSecret = ""
$MailTenantID = ""
$MailSender = ""
$MailTo = ""


#Connect to GRAPH API
$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $MailclientId
    Client_Secret = $MailclientSecret

}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$MailtenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
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