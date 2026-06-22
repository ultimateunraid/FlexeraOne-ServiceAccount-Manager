#==============================================
# Flexera One: Service Account Manager (GUI)
#==============================================
# Requires: PowerShell 5.1, Windows
# Logs to:  .\Logs\FlexeraSAM_YYYYMMDD.log
#==============================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Windows.Forms.Application]::EnableVisualStyles()

#region --- Logging ---

$script:LogFolder = Join-Path $PSScriptRoot 'Logs'
if (-not (Test-Path $script:LogFolder)) {
    New-Item -ItemType Directory -Path $script:LogFolder | Out-Null
}
$script:LogFile = Join-Path $script:LogFolder ("FlexeraSAM_" + (Get-Date -Format 'yyyyMMdd') + '.log')

function Write-Log {
    param (
        [string]$Level,   # INFO | SUCCESS | WARN | ERROR
        [string]$Message
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$($Level.ToUpper().PadRight(7))] $Message"
    Add-Content -Path $script:LogFile -Value $line
}

Write-Log INFO "Session started. Log: $($script:LogFile)"

#endregion

#region --- Helpers ---

function ConvertTo-PlainText {
    param ([System.Security.SecureString]$SecureString)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Get-RegionUrls {
    param ([string]$Region)
    switch ($Region) {
        'EU'    { return @{ Auth = 'https://login.flexera.eu/oidc/token';     Api = 'https://api.flexera.eu' } }
        'AU'    { return @{ Auth = 'https://login.flexera.com.au/oidc/token'; Api = 'https://api.flexera.com.au' } }
        default { return @{ Auth = 'https://login.flexera.com/oidc/token';    Api = 'https://api.flexera.com' } }
    }
}

function Get-ApiErrorMessage {
    param ($ErrorRecord)
    $code = $null
    if ($ErrorRecord.Exception.Response) {
        $code = [int]$ErrorRecord.Exception.Response.StatusCode
    }
    # ErrorDetails.Message is captured by PS5 before the stream closes - most reliable
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $body = $ErrorRecord.ErrorDetails.Message
        Write-Log WARN "API error body: $body"
        try {
            $parsed = $body | ConvertFrom-Json
            if ($parsed.message) { return "HTTP $code - $($parsed.message)" }
        } catch { }
        return "HTTP $code - $body"
    }
    if ($code) { return "HTTP $code - $($ErrorRecord.Exception.Message)" }
    return $ErrorRecord.Exception.Message
}

# Safely coerce a value to string - ListViewItem.SubItems.Add() throws on $null
function Safe-Str {
    param ($Value)
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

# Render the credential-status cell. $null = could not determine (endpoint error).
function Format-CredCell {
    param ($Count)
    if ($null -eq $Count) { return '?' }
    if ([int]$Count -gt 0) { return "Yes ($Count)" }
    return 'No'
}

#endregion

#region --- API Functions ---

function Invoke-Connect {
    param ([string]$OrgId, [string]$RefreshToken, [string]$Region)

    $urls = Get-RegionUrls -Region $Region
    Write-Log INFO "AUTH | POST $($urls.Auth) | OrgId=$OrgId Region=$Region"
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $urls.Auth `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{ grant_type = 'refresh_token'; refresh_token = $RefreshToken }

        $script:AccessToken = $resp.access_token
        $script:ApiBase     = $urls.Api
        $script:OrgId       = $OrgId
        $script:Headers     = @{
            Authorization  = "Bearer $($script:AccessToken)"
            'Content-Type' = 'application/json'
            Accept         = 'application/json'
        }
        Write-Log SUCCESS "AUTH | Token obtained. Expires in $($resp.expires_in)s."
        return $true
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "AUTH | Failed: $msg"
        return "Auth failed: $msg"
    }
}

function ConvertTo-GrantRef {
    # Converts 'iam#service-account:10827' -> 'ref:nam:::iam:service-account:10827'
    # Service accounts (like users) use empty org segment - no orgId in the middle.
    param ([string]$IamRef)
    if ($IamRef -match '^iam#(.+)$') {
        return "ref:nam:::iam:$($Matches[1])"
    }
    # Already in ref:nam format or unknown - return as-is
    return $IamRef
}

function Unwrap-ApiResponse {
    param ($Response)
    # Flexera One endpoints return either a plain array or {"values":[...]}
    if ($Response -is [array]) { return $Response }
    if ($null -ne $Response.values) { return $Response.values }
    return @($Response)
}

function Get-AvailableRoles {
    $pageSize = 100
    $offset   = 0
    $all      = @()

    Write-Log INFO "GET  | Fetching all roles (paginated, page size $pageSize)..."
    try {
        do {
            $uri  = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/roles?view=extended&limit=$pageSize&offset=$offset"
            Write-Log INFO "GET  | $uri"
            $resp  = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
            $page  = Unwrap-ApiResponse $resp
            $all  += $page
            $offset += $pageSize
        } while ($page.Count -eq $pageSize)

        Write-Log SUCCESS "GET  | Roles retrieved: $($all.Count) total."
        return $all
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "GET  | Failed to retrieve roles: $msg"
        return $null
    }
}

function New-ServiceAccount {
    param ([string]$Name, [string]$Description)

    $uri  = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts"
    $body = @{ name = $Name }
    if ($Description -ne '') { $body['description'] = $Description }

    Write-Log INFO "POST | $uri | Name='$Name' Description='$Description'"
    try {
        # API returns empty body on success - follow up with GET to retrieve details
        $null = Invoke-RestMethod -Method Post -Uri $uri `
            -Headers $script:Headers `
            -Body ($body | ConvertTo-Json -Depth 3)
        Write-Log SUCCESS "POST | Service account '$Name' created (empty response body - fetching details)."

        $accounts = Get-ServiceAccounts
        $created  = $accounts | Where-Object { $_.name -eq $Name } |
                    Sort-Object id -Descending | Select-Object -First 1

        if ($created) {
            Write-Log SUCCESS "POST | Retrieved created account. ID=$($created.id) Ref=$($created.ref)"
        } else {
            Write-Log WARN "POST | Could not find '$Name' in account list after creation."
        }
        return $created
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "POST | Failed to create service account '$Name': $msg"
        throw $msg
    }
}

function New-ServiceAccountClient {
    # Generates a client (clientId + clientSecret) for an existing service account.
    # The clientSecret is returned by the API ONCE and cannot be retrieved later.
    param ([string]$ServiceAccountId)

    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts/$ServiceAccountId/clients"
    Write-Log INFO "POST | $uri | Generating client credentials for SA ID=$ServiceAccountId"
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:Headers
        # Never log the secret - only confirm the clientId was issued.
        Write-Log SUCCESS "POST | Client credentials generated. clientId=$($resp.clientId)"
        return $resp
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "POST | Failed to generate client credentials for SA ID=${ServiceAccountId}: $msg"
        throw $msg
    }
}

function Get-ServiceAccountClients {
    # Lists the clients (credentials) of a service account. Secrets are NOT returned -
    # only metadata (clientId, createdAt, etc). Used to show credential status and to
    # detect existing credentials before generating new ones.
    # NOTE: this endpoint is not covered by public docs; caller must handle errors.
    param ([string]$ServiceAccountId)

    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts/$ServiceAccountId/clients"
    Write-Log INFO "GET  | $uri"
    $resp  = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
    $items = @(Unwrap-ApiResponse $resp) | Where-Object { $null -ne $_ }
    return @($items)
}

function Remove-ServiceAccountClient {
    # Deletes a single client (credential) from a service account by clientId.
    param ([string]$ServiceAccountId, [string]$ClientId)

    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts/$ServiceAccountId/clients/$ClientId"
    Write-Log INFO "DELETE | $uri | Deleting client '$ClientId' from SA ID=$ServiceAccountId"
    try {
        $null = Invoke-RestMethod -Method Delete -Uri $uri -Headers $script:Headers
        Write-Log SUCCESS "DELETE | Client '$ClientId' deleted from SA ID=$ServiceAccountId."
        return $true
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "DELETE | Failed to delete client '$ClientId' from SA ID=${ServiceAccountId}: $msg"
        throw $msg
    }
}

function Invoke-AssignRoles {
    param ([string]$SubjectRef, [string[]]$Roles, [string]$ScopeRef)

    $uri        = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/access-rules/grant"
    $grantRef   = ConvertTo-GrantRef -IamRef $SubjectRef
    $results    = @()

    Write-Log INFO "PUT  | Subject ref converted: '$SubjectRef' -> '$grantRef'"

    foreach ($role in $Roles) {
        $payload = @{
            role    = @{ name = $role }
            scope   = @{ ref  = $ScopeRef }
            subject = @{ ref  = $grantRef }
        } | ConvertTo-Json -Depth 5

        Write-Log INFO "PUT  | $uri | Role='$role' Subject='$grantRef' Scope='$ScopeRef'"
        try {
            $null = Invoke-RestMethod -Method Put -Uri $uri -Headers $script:Headers -Body $payload
            Write-Log SUCCESS "PUT  | Role '$role' assigned to '$SubjectRef'."
            $results += [PSCustomObject]@{ Role = $role; Status = 'Assigned' }
        }
        catch {
            $msg = Get-ApiErrorMessage $_
            Write-Log ERROR "PUT  | Failed to assign role '$role' to '$SubjectRef': $msg"
            $results += [PSCustomObject]@{ Role = $role; Status = "Failed: $msg" }
        }
    }
    return $results
}

function Invoke-RevokeRole {
    param ([string]$SubjectRef, [string]$RoleName, [string]$ScopeRef)

    $uri      = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/access-rules/revoke"
    $grantRef = ConvertTo-GrantRef -IamRef $SubjectRef

    $payload = @{
        role    = @{ name = $RoleName }
        scope   = @{ ref  = $ScopeRef }
        subject = @{ ref  = $grantRef }
    } | ConvertTo-Json -Depth 5

    Write-Log INFO "PUT  | $uri | Role='$RoleName' Subject='$grantRef' Scope='$ScopeRef'"
    try {
        $null = Invoke-RestMethod -Method Put -Uri $uri -Headers $script:Headers -Body $payload
        Write-Log SUCCESS "PUT  | Role '$RoleName' revoked from '$SubjectRef'."
        return $true
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "PUT  | Failed to revoke role '$RoleName' from '$SubjectRef': $msg"
        throw $msg
    }
}

function Get-AssignedRoles {
    param ([string]$SubjectRef)

    # OData filter on subjectRef fails with 400 when the value contains '#' or ':'
    # Fetch all access rules and filter client-side instead
    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/access-rules?view=extended"

    Write-Log INFO "GET  | $uri (filtering client-side for '$SubjectRef')"
    try {
        $resp  = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
        $all      = Unwrap-ApiResponse $resp
        $grantRef = ConvertTo-GrantRef -IamRef $SubjectRef
        Write-Log INFO "GET  | Total access rules returned: $($all.Count). Filtering for '$grantRef'"

        # Log any service-account rules found so we can verify the stored format
        $saRules = @($all | Where-Object { $_.subject.ref -like '*service-account*' })
        if ($saRules.Count -gt 0) {
            Write-Log INFO "GET  | Found $($saRules.Count) service-account rule(s). First: $($saRules[0] | ConvertTo-Json -Depth 5 -Compress)"
        } else {
            Write-Log INFO "GET  | No service-account rules found in response."
        }

        $match = @($all | Where-Object { $_.subject.ref -eq $grantRef })
        Write-Log SUCCESS "GET  | $($match.Count) role(s) found for '$grantRef' (of $($all.Count) total rules)."
        return $match
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "GET  | Failed to retrieve access rules: $msg"
        throw $msg
    }
}

function Get-ServiceAccounts {
    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts"
    Write-Log INFO "GET  | $uri"
    try {
        $resp  = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
        $items = Unwrap-ApiResponse $resp
        Write-Log SUCCESS "GET  | $($items.Count) service account(s) retrieved."
        Write-Log INFO "GET  | Raw SA list response: $($resp | ConvertTo-Json -Depth 5 -Compress)"
        return $items
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "GET  | Failed to retrieve service accounts: $msg"
        throw $msg
    }
}

function Remove-ServiceAccount {
    param ([string]$AccountId, [string]$AccountName)

    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/service-accounts/$AccountId"
    Write-Log INFO "DELETE | $uri | Name='$AccountName' ID='$AccountId'"
    try {
        $null = Invoke-RestMethod -Method Delete -Uri $uri -Headers $script:Headers
        Write-Log SUCCESS "DELETE | Service account '$AccountName' ($AccountId) deleted."
        return $true
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "DELETE | Failed to delete '$AccountName' ($AccountId): $msg"
        throw $msg
    }
}

#endregion

#region --- UI Helpers ---

$FONT_LABEL  = New-Object System.Drawing.Font('Segoe UI', 9)
$FONT_BOLD   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$COLOR_PANEL = [System.Drawing.Color]::FromArgb(245, 245, 245)
$COLOR_ACCENT= [System.Drawing.Color]::FromArgb(0, 114, 198)

function New-Label {
    param ([string]$Text, [int]$X, [int]$Y, [int]$W = 120, [int]$H = 20)
    $l = New-Object System.Windows.Forms.Label
    $l.Text     = $Text
    $l.Location = New-Object System.Drawing.Point($X, $Y)
    $l.Size     = New-Object System.Drawing.Size($W, $H)
    $l.Font     = $FONT_LABEL
    return $l
}

function New-TextBox {
    param ([int]$X, [int]$Y, [int]$W = 220, [bool]$Password = $false)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($X, $Y)
    $t.Size     = New-Object System.Drawing.Size($W, 22)
    $t.Font     = $FONT_LABEL
    if ($Password) { $t.PasswordChar = [char]0x25CF }
    return $t
}

function New-Button {
    param ([string]$Text, [int]$X, [int]$Y, [int]$W = 100, [int]$H = 28)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.Font      = $FONT_BOLD
    $b.BackColor = $COLOR_ACCENT
    $b.ForeColor = [System.Drawing.Color]::White
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize = 0
    return $b
}

function New-ListView {
    param ([int]$X, [int]$Y, [int]$W, [int]$H, [string[]]$Columns)
    $lv = New-Object System.Windows.Forms.ListView
    $lv.Location      = New-Object System.Drawing.Point($X, $Y)
    $lv.Size          = New-Object System.Drawing.Size($W, $H)
    $lv.View          = [System.Windows.Forms.View]::Details
    $lv.FullRowSelect = $true
    $lv.GridLines     = $true
    $lv.Scrollable    = $true
    $lv.Font          = $FONT_LABEL
    foreach ($col in $Columns) { $null = $lv.Columns.Add($col, -2) }
    return $lv
}

function Set-Status {
    param ([string]$Message, [string]$Color = 'Black')
    $script:StatusLabel.Text      = $Message
    $script:StatusLabel.ForeColor = [System.Drawing.Color]::$Color
    $script:Form.Refresh()
}

function Populate-RoleListBoxes {
    param ([array]$Roles)
    foreach ($lb in @($script:LbCreateRoles, $script:LbAssignRoles)) {
        $lb.Items.Clear()
        foreach ($r in ($Roles | Sort-Object name)) {
            $null = $lb.Items.Add((Safe-Str $r.name))
        }
    }

    $script:LvAvailableRoles.BeginUpdate()
    $script:LvAvailableRoles.Items.Clear()
    foreach ($r in ($Roles | Sort-Object name)) {
        $item = New-Object System.Windows.Forms.ListViewItem((Safe-Str $r.name))
        $null = $item.SubItems.Add((Safe-Str $r.displayName))
        $null = $item.SubItems.Add((Safe-Str $r.category))
        $null = $item.SubItems.Add((Safe-Str $r.description))
        $null = $script:LvAvailableRoles.Items.Add($item)
    }
    # Fixed widths prevent the Description column expanding to thousands of pixels
    # which causes ListView to clip rows instead of scrolling vertically
    $script:LvAvailableRoles.Columns[0].Width = 160   # Role Name
    $script:LvAvailableRoles.Columns[1].Width = 160   # Display Name
    $script:LvAvailableRoles.Columns[2].Width = 110   # Category
    $script:LvAvailableRoles.Columns[3].Width = 340   # Description
    $script:LvAvailableRoles.EndUpdate()
}

function Show-CredentialsDialog {
    # Modal "copy once" dialog. The clientSecret cannot be retrieved again, so this
    # is the user's single chance to copy/save it.
    param ([string]$AccountName, [string]$ClientId, [string]$ClientSecret)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "Client Credentials - $AccountName"
    $dlg.Size            = New-Object System.Drawing.Size(620, 250)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.MinimizeBox     = $false
    $dlg.BackColor       = $COLOR_PANEL
    $dlg.Font            = $FONT_LABEL

    $lblWarn = New-Object System.Windows.Forms.Label
    $lblWarn.Text      = [char]0x26A0 + ' Copy the Client Secret now. It is shown ONCE and cannot be retrieved again - only regenerated.'
    $lblWarn.Location  = New-Object System.Drawing.Point(15, 12)
    $lblWarn.Size      = New-Object System.Drawing.Size(585, 36)
    $lblWarn.ForeColor = [System.Drawing.Color]::FromArgb(180, 40, 40)
    $lblWarn.Font      = $FONT_BOLD

    $lblId = New-Label 'Client ID:' 15 58 90
    $txtId = New-Object System.Windows.Forms.TextBox
    $txtId.Location = New-Object System.Drawing.Point(105, 56)
    $txtId.Size     = New-Object System.Drawing.Size(390, 22)
    $txtId.Font     = $FONT_LABEL
    $txtId.ReadOnly = $true
    $txtId.Text     = $ClientId
    $btnCopyId = New-Button 'Copy' 505 55 90 26

    $lblSecret = New-Label 'Client Secret:' 15 92 90
    $txtSecret = New-Object System.Windows.Forms.TextBox
    $txtSecret.Location = New-Object System.Drawing.Point(105, 90)
    $txtSecret.Size     = New-Object System.Drawing.Size(390, 22)
    $txtSecret.Font     = $FONT_LABEL
    $txtSecret.ReadOnly = $true
    $txtSecret.Text     = $ClientSecret
    $btnCopySecret = New-Button 'Copy' 505 89 90 26

    $btnSave  = New-Button 'Save to File...' 105 130 130 28
    $btnClose = New-Button 'Close'           465 130 130 28

    $lblCopied = New-Object System.Windows.Forms.Label
    $lblCopied.Location  = New-Object System.Drawing.Point(245, 136)
    $lblCopied.Size      = New-Object System.Drawing.Size(210, 18)
    $lblCopied.Font      = $FONT_LABEL
    $lblCopied.ForeColor = [System.Drawing.Color]::DarkGreen
    $lblCopied.Text      = ''

    $btnCopyId.Add_Click({
        Set-Clipboard -Value $ClientId
        $lblCopied.Text = 'Client ID copied.'
        Write-Log INFO 'Client ID copied to clipboard from credentials dialog.'
    })
    $btnCopySecret.Add_Click({
        Set-Clipboard -Value $ClientSecret
        $lblCopied.Text = 'Client Secret copied.'
        Write-Log INFO 'Client Secret copied to clipboard from credentials dialog.'
    })
    $btnSave.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter   = 'Text file (*.txt)|*.txt'
        $sfd.FileName = "FlexeraSA_$($AccountName -replace '[^\w\-]', '_')_credentials.txt"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $content = @(
                "Flexera One Service Account Credentials"
                "Account : $AccountName"
                "Org ID  : $($script:OrgId)"
                "Saved   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                ""
                "clientId     : $ClientId"
                "clientSecret : $ClientSecret"
            ) -join "`r`n"
            Set-Content -Path $sfd.FileName -Value $content -Encoding UTF8
            $lblCopied.Text = 'Saved to file.'
            Write-Log INFO "Credentials saved to file: $($sfd.FileName)"
        }
    })
    $btnClose.Add_Click({ $dlg.Close() })
    $dlg.AcceptButton = $btnClose

    $dlg.Controls.AddRange(@(
        $lblWarn, $lblId, $txtId, $btnCopyId,
        $lblSecret, $txtSecret, $btnCopySecret,
        $btnSave, $btnClose, $lblCopied
    ))
    $null = $dlg.ShowDialog($script:Form)
    $dlg.Dispose()
}

function Update-ClientListView {
    # (Re)loads a service account's clients into a ListView. Returns the client count,
    # or -1 if the listing failed.
    param ($Lv, [string]$ServiceAccountId, $StatusLabel)

    $Lv.BeginUpdate()
    $Lv.Items.Clear()
    if ($StatusLabel) { $StatusLabel.Text = 'Loading clients...'; $StatusLabel.ForeColor = [System.Drawing.Color]::Gray }
    try {
        $clients = @(Get-ServiceAccountClients -ServiceAccountId $ServiceAccountId)
        foreach ($c in $clients) {
            $row = New-Object System.Windows.Forms.ListViewItem((Safe-Str $c.clientId))
            $null = $row.SubItems.Add((Safe-Str $c.createdAt))
            $null = $row.SubItems.Add((Safe-Str $c.createdBy))
            $null = $row.SubItems.Add((Safe-Str $c.kind))
            $row.Tag = $c
            $null = $Lv.Items.Add($row)
        }
        $Lv.Columns[0].Width = 230
        $Lv.Columns[1].Width = 170
        $Lv.Columns[2].Width = 110
        $Lv.Columns[3].Width = 170
        $Lv.EndUpdate()
        if ($StatusLabel) {
            $StatusLabel.Text      = "$($clients.Count) client(s)."
            $StatusLabel.ForeColor = [System.Drawing.Color]::Black
        }
        return $clients.Count
    }
    catch {
        $Lv.EndUpdate()
        $msg = Get-ApiErrorMessage $_
        if ($StatusLabel) { $StatusLabel.Text = "Failed to list clients: $msg"; $StatusLabel.ForeColor = [System.Drawing.Color]::Red }
        Write-Log ERROR "Manage Clients | list failed for SA ID=${ServiceAccountId}: $msg"
        return -1
    }
}

function Show-ClientManagerDialog {
    # Per-account client manager: list, create (copy-once secret), and delete clients.
    param ([string]$AccountName, [string]$ServiceAccountId)

    $aTLR = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $aAll = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $aBL  = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $aBR  = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "Manage Clients - $AccountName (ID $ServiceAccountId)"
    $dlg.Size            = New-Object System.Drawing.Size(740, 470)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(640, 360)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.BackColor       = $COLOR_PANEL
    $dlg.Font            = $FONT_LABEL

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text      = 'A service account can have multiple clients. Best practice: keep only one in active use. To rotate without downtime, create a new client, switch your app to it, then delete the old one.'
    $lblInfo.Location  = New-Object System.Drawing.Point(12, 10)
    $lblInfo.Size      = New-Object System.Drawing.Size(704, 34)
    $lblInfo.ForeColor = [System.Drawing.Color]::DimGray
    $lblInfo.Anchor    = $aTLR

    $lvClients = New-ListView 12 50 704 300 @('Client ID','Created At','Created By','Kind')
    $lvClients.MultiSelect   = $false
    $lvClients.HideSelection = $false
    $lvClients.Anchor        = $aAll

    $btnCreateClient = New-Button 'Create New Client' 12 360 150 30
    $btnCreateClient.Anchor  = $aBL

    $btnDeleteClient = New-Button 'Delete Selected' 172 360 130 30
    $btnDeleteClient.BackColor = [System.Drawing.Color]::FromArgb(180, 40, 40)
    $btnDeleteClient.Enabled   = $false
    $btnDeleteClient.Anchor    = $aBL

    $btnRefreshClients = New-Button 'Refresh' 312 360 90 30
    $btnRefreshClients.Anchor  = $aBL

    $btnCloseClients = New-Button 'Close' 626 360 90 30
    $btnCloseClients.Anchor    = $aBR

    $lblDlgStatus = New-Object System.Windows.Forms.Label
    $lblDlgStatus.Location  = New-Object System.Drawing.Point(12, 398)
    $lblDlgStatus.Size      = New-Object System.Drawing.Size(704, 18)
    $lblDlgStatus.Font      = New-Object System.Drawing.Font('Segoe UI', 8)
    $lblDlgStatus.ForeColor = [System.Drawing.Color]::Black
    $lblDlgStatus.Anchor    = ([System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

    $lvClients.Add_SelectedIndexChanged({
        $btnDeleteClient.Enabled = ($lvClients.SelectedItems.Count -eq 1)
    })

    $btnRefreshClients.Add_Click({
        $null = Update-ClientListView -Lv $lvClients -ServiceAccountId $ServiceAccountId -StatusLabel $lblDlgStatus
        $btnDeleteClient.Enabled = $false
    })

    $btnCreateClient.Add_Click({
        $existing = $lvClients.Items.Count
        if ($existing -gt 0) {
            $proceed = [System.Windows.Forms.MessageBox]::Show(
                "This service account already has $existing client(s). A new client will be ADDED (existing clients keep working).`n`nContinue?",
                'Create New Client',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Information)
            if ($proceed -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
        $lblDlgStatus.Text = 'Creating client...'; $lblDlgStatus.ForeColor = [System.Drawing.Color]::Gray
        try {
            $client = New-ServiceAccountClient -ServiceAccountId $ServiceAccountId
            if (-not $client.clientId) { throw 'Response did not contain a clientId.' }
            Show-CredentialsDialog -AccountName $AccountName `
                -ClientId (Safe-Str $client.clientId) `
                -ClientSecret (Safe-Str $client.clientSecret)
            $null = Update-ClientListView -Lv $lvClients -ServiceAccountId $ServiceAccountId -StatusLabel $lblDlgStatus
            $btnDeleteClient.Enabled = $false
        }
        catch {
            $lblDlgStatus.Text = "Create failed: $_"; $lblDlgStatus.ForeColor = [System.Drawing.Color]::Red
            [System.Windows.Forms.MessageBox]::Show("Error: $_", 'Create Failed',
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    })

    $btnDeleteClient.Add_Click({
        if ($lvClients.SelectedItems.Count -ne 1) { return }
        $sel      = $lvClients.SelectedItems[0]
        $clientId = $sel.Text
        $confirm  = [System.Windows.Forms.MessageBox]::Show(
            "Delete client '$clientId'?`n`nAny application authenticating with this clientId/secret will immediately stop working. This cannot be undone.",
            'Confirm Delete Client',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $lblDlgStatus.Text = "Deleting client '$clientId'..."; $lblDlgStatus.ForeColor = [System.Drawing.Color]::Gray
        try {
            $null = Remove-ServiceAccountClient -ServiceAccountId $ServiceAccountId -ClientId $clientId
            $null = Update-ClientListView -Lv $lvClients -ServiceAccountId $ServiceAccountId -StatusLabel $lblDlgStatus
            $btnDeleteClient.Enabled = $false
        }
        catch {
            $lblDlgStatus.Text = "Delete failed: $_"; $lblDlgStatus.ForeColor = [System.Drawing.Color]::Red
            [System.Windows.Forms.MessageBox]::Show("Error: $_", 'Delete Failed',
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    })

    $btnCloseClients.Add_Click({ $dlg.Close() })
    $dlg.AcceptButton = $btnCloseClients

    $dlg.Controls.AddRange(@(
        $lblInfo, $lvClients,
        $btnCreateClient, $btnDeleteClient, $btnRefreshClients, $btnCloseClients,
        $lblDlgStatus
    ))
    $dlg.Add_Shown({ $null = Update-ClientListView -Lv $lvClients -ServiceAccountId $ServiceAccountId -StatusLabel $lblDlgStatus })
    $null = $dlg.ShowDialog($script:Form)
    $dlg.Dispose()
}

#endregion

#region --- Build Form ---

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text            = 'Flexera One - Service Account Manager'
$script:Form.Size            = New-Object System.Drawing.Size(780, 700)
$script:Form.MinimumSize     = New-Object System.Drawing.Size(780, 600)
$script:Form.StartPosition   = 'CenterScreen'
$script:Form.FormBorderStyle = 'Sizable'
$script:Form.BackColor       = $COLOR_PANEL
$script:Form.Font            = $FONT_LABEL

# ---- Connection GroupBox ----
$AnchorTLR  = [System.Windows.Forms.AnchorStyles]::Top  -bor [System.Windows.Forms.AnchorStyles]::Left  -bor [System.Windows.Forms.AnchorStyles]::Right
$AnchorAll  = [System.Windows.Forms.AnchorStyles]::Top  -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$AnchorBLR  = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

$gbConn          = New-Object System.Windows.Forms.GroupBox
$gbConn.Text     = 'Connection'
$gbConn.Location = New-Object System.Drawing.Point(10, 8)
$gbConn.Size     = New-Object System.Drawing.Size(744, 80)
$gbConn.Font     = $FONT_BOLD
$gbConn.Anchor   = $AnchorTLR

$lblOrg   = New-Label 'Org ID:'        12  22  60
$txtOrgId = New-TextBox                75  20  120

$lblRegion = New-Label 'Region:'      210  22  50
$cbRegion  = New-Object System.Windows.Forms.ComboBox
$cbRegion.Location      = New-Object System.Drawing.Point(263, 20)
$cbRegion.Size          = New-Object System.Drawing.Size(60, 22)
$cbRegion.DropDownStyle = 'DropDownList'
$cbRegion.Font          = $FONT_LABEL
@('US','EU','AU') | ForEach-Object { $null = $cbRegion.Items.Add($_) }
$cbRegion.SelectedIndex = 0

$lblToken = New-Label 'Refresh Token:' 338  22  95
$txtToken = New-TextBox                436  20  180  $true

$btnConnect = New-Button 'Connect' 630 18 100

$script:ConnectIndicator          = New-Object System.Windows.Forms.Label
$script:ConnectIndicator.Location = New-Object System.Drawing.Point(630, 50)
$script:ConnectIndicator.Size     = New-Object System.Drawing.Size(100, 18)
$script:ConnectIndicator.Font     = $FONT_LABEL
$script:ConnectIndicator.Text     = ''
$script:ConnectIndicator.ForeColor= [System.Drawing.Color]::Gray

$gbConn.Controls.AddRange(@($lblOrg, $txtOrgId, $lblRegion, $cbRegion,
                             $lblToken, $txtToken, $btnConnect, $script:ConnectIndicator))
$script:Form.Controls.Add($gbConn)

# ---- Tab Control ----
$tabs          = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(10, 96)
$tabs.Size     = New-Object System.Drawing.Size(744, 538)
$tabs.Font     = $FONT_LABEL
$tabs.Anchor   = $AnchorAll
$script:Form.Controls.Add($tabs)

#--------------------------------------------
# TAB 1: Create Account
#--------------------------------------------
$tabCreate      = New-Object System.Windows.Forms.TabPage
$tabCreate.Text = '  Create Account  '

$lblCName = New-Label 'Account Name: *' 10 16 110
$txtCName = New-TextBox 125 14 280

$lblCDesc = New-Label 'Description:'   10 48 110
$txtCDesc = New-TextBox 125 46 280

$lblCScopeRef = New-Label 'Scope Ref:' 10 80 110
$txtCScopeRef = New-TextBox 125 78 340
$tipScope = New-Object System.Windows.Forms.ToolTip
$tipScope.SetToolTip($txtCScopeRef, 'Auto-populated from Org ID. Override if needed.')

$lblCRoles     = New-Label 'Assign Roles:' 10 116 110
$lblCRolesHint = New-Object System.Windows.Forms.Label
$lblCRolesHint.Text      = '(Ctrl+Click to multi-select; leave blank to skip)'
$lblCRolesHint.Location  = New-Object System.Drawing.Point(125, 117)
$lblCRolesHint.Size      = New-Object System.Drawing.Size(330, 16)
$lblCRolesHint.Font      = New-Object System.Drawing.Font('Segoe UI', 8)
$lblCRolesHint.ForeColor = [System.Drawing.Color]::Gray

$script:LbCreateRoles                = New-Object System.Windows.Forms.ListBox
$script:LbCreateRoles.Location       = New-Object System.Drawing.Point(125, 136)
$script:LbCreateRoles.Size           = New-Object System.Drawing.Size(340, 180)
$script:LbCreateRoles.SelectionMode  = 'MultiExtended'
$script:LbCreateRoles.ScrollAlwaysVisible = $true
$script:LbCreateRoles.Font           = $FONT_LABEL
$script:LbCreateRoles.Anchor         = $AnchorTLR
$null = $script:LbCreateRoles.Items.Add('Connect first to load available roles')

$btnCreate             = New-Button 'Create Account' 125 328 140
$script:LvCreateResult = New-ListView 10 368 710 120 @('Field','Value')
$script:LvCreateResult.Anchor        = $AnchorBLR

$tabCreate.Controls.AddRange(@(
    $lblCName, $txtCName, $lblCDesc, $txtCDesc,
    $lblCScopeRef, $txtCScopeRef,
    $lblCRoles, $lblCRolesHint, $script:LbCreateRoles,
    $btnCreate, $script:LvCreateResult
))
$tabs.TabPages.Add($tabCreate)

#--------------------------------------------
# TAB 2: Assign Roles
#--------------------------------------------
$tabAssign      = New-Object System.Windows.Forms.TabPage
$tabAssign.Text = '  Assign Roles  '

$lblASubj = New-Label 'Subject Ref: *'  10  16  110
$txtASubj = New-TextBox 125 14 400

$lblAScopeRef = New-Label 'Scope Ref: *' 10 48 110
$txtAScopeRef = New-TextBox 125 46 340
$tipScope.SetToolTip($txtAScopeRef, 'Auto-populated from Org ID. Override if needed.')

$lblARoles     = New-Label 'Roles: *'    10 84 110
$lblARolesHint = New-Object System.Windows.Forms.Label
$lblARolesHint.Text      = '(Ctrl+Click to multi-select)'
$lblARolesHint.Location  = New-Object System.Drawing.Point(125, 85)
$lblARolesHint.Size      = New-Object System.Drawing.Size(250, 16)
$lblARolesHint.Font      = New-Object System.Drawing.Font('Segoe UI', 8)
$lblARolesHint.ForeColor = [System.Drawing.Color]::Gray

$script:LbAssignRoles               = New-Object System.Windows.Forms.ListBox
$script:LbAssignRoles.Location      = New-Object System.Drawing.Point(125, 104)
$script:LbAssignRoles.Size          = New-Object System.Drawing.Size(340, 190)
$script:LbAssignRoles.SelectionMode = 'MultiExtended'
$script:LbAssignRoles.ScrollAlwaysVisible = $true
$script:LbAssignRoles.Font          = $FONT_LABEL
$script:LbAssignRoles.Anchor        = $AnchorTLR
$null = $script:LbAssignRoles.Items.Add('Connect first to load available roles')

$btnAssign             = New-Button 'Assign Roles' 125 306 120
$script:LvAssignResult = New-ListView 10 344 710 140 @('Role','Status')
$script:LvAssignResult.Anchor       = $AnchorBLR

$tabAssign.Controls.AddRange(@(
    $lblASubj, $txtASubj, $lblAScopeRef, $txtAScopeRef,
    $lblARoles, $lblARolesHint, $script:LbAssignRoles,
    $btnAssign, $script:LvAssignResult
))
$tabs.TabPages.Add($tabAssign)

#--------------------------------------------
# TAB 3: View Assigned Roles
#--------------------------------------------
$tabView      = New-Object System.Windows.Forms.TabPage
$tabView.Text = '  View Assigned Roles  '

$lblVSubj = New-Label 'Subject Ref: *' 10 16 110
$txtVSubj = New-TextBox 125 14 360
$btnView  = New-Button 'Get Roles' 495 12 110

$btnRevokeRole           = New-Button 'Revoke Selected' 615 12 110
$btnRevokeRole.BackColor = [System.Drawing.Color]::FromArgb(180, 40, 40)
$btnRevokeRole.Enabled   = $false

$script:LvViewResult = New-ListView 10 46 710 446 @('Role Name','Display Name','Category','Assigned At')
$script:LvViewResult.Dock          = [System.Windows.Forms.DockStyle]::None
$script:LvViewResult.Anchor        = $AnchorAll
$script:LvViewResult.MultiSelect   = $true
$script:LvViewResult.HideSelection = $false

$tabView.Controls.AddRange(@($lblVSubj, $txtVSubj, $btnView, $btnRevokeRole, $script:LvViewResult))
$tabs.TabPages.Add($tabView)

#--------------------------------------------
# TAB 4: Browse Available Roles
#--------------------------------------------
$tabBrowse         = New-Object System.Windows.Forms.TabPage
$tabBrowse.Text    = '  Available Roles  '
$tabBrowse.Padding = New-Object System.Windows.Forms.Padding(0)

$script:LvAvailableRoles      = New-ListView 0 0 0 0 @('Role Name','Display Name','Category','Description')
$script:LvAvailableRoles.Dock = [System.Windows.Forms.DockStyle]::Fill

$tabBrowse.Controls.Add($script:LvAvailableRoles)
$tabs.TabPages.Add($tabBrowse)

#--------------------------------------------
# TAB 5: Manage Accounts
#--------------------------------------------
$tabManage      = New-Object System.Windows.Forms.TabPage
$tabManage.Text = '  Manage Accounts  '

$btnLoadAccounts          = New-Button 'Load Accounts' 10 10 110 26
$txtManageFilter          = New-Object System.Windows.Forms.TextBox
$txtManageFilter.Location = New-Object System.Drawing.Point(128, 13)
$txtManageFilter.Size     = New-Object System.Drawing.Size(150, 22)
$txtManageFilter.Font     = $FONT_LABEL
$txtManageFilter.Text     = 'Filter by name...'
$txtManageFilter.ForeColor= [System.Drawing.Color]::Gray

$btnManageClients          = New-Button 'Manage Clients...' 286 10 160 26
$btnManageClients.Enabled  = $false

$btnDeleteSelected          = New-Button 'Delete Selected' 454 10 130 26
$btnDeleteSelected.BackColor= [System.Drawing.Color]::FromArgb(180, 40, 40)
$btnDeleteSelected.Enabled  = $false

$lblManageCount          = New-Object System.Windows.Forms.Label
$lblManageCount.Location = New-Object System.Drawing.Point(592, 14)
$lblManageCount.Size     = New-Object System.Drawing.Size(128, 18)
$lblManageCount.Font     = New-Object System.Drawing.Font('Segoe UI', 8)
$lblManageCount.ForeColor= [System.Drawing.Color]::Gray
$lblManageCount.Text     = ''

$script:LvManageAccounts = New-ListView 10 46 710 440 @('Name','Credentials','ID','Subject Ref (iam#)','Subject Ref (API format)','Created By')
$script:LvManageAccounts.MultiSelect    = $true
$script:LvManageAccounts.HideSelection  = $false
$script:LvManageAccounts.Anchor         = $AnchorAll

# Right-click context menu
$ctxManage      = New-Object System.Windows.Forms.ContextMenuStrip
$mnuCopyRef     = New-Object System.Windows.Forms.ToolStripMenuItem
$mnuCopyRef.Text   = 'Copy Subject Ref (iam# format)'
$mnuCopyApiRef     = New-Object System.Windows.Forms.ToolStripMenuItem
$mnuCopyApiRef.Text= 'Copy Subject Ref (API format)'
$mnuCopyId         = New-Object System.Windows.Forms.ToolStripMenuItem
$mnuCopyId.Text    = 'Copy ID'
$mnuCopyName       = New-Object System.Windows.Forms.ToolStripMenuItem
$mnuCopyName.Text  = 'Copy Name'
$null = $ctxManage.Items.Add($mnuCopyRef)
$null = $ctxManage.Items.Add($mnuCopyApiRef)
$null = $ctxManage.Items.Add($mnuCopyId)
$null = $ctxManage.Items.Add($mnuCopyName)
$script:LvManageAccounts.ContextMenuStrip = $ctxManage

$tabManage.Controls.AddRange(@(
    $btnLoadAccounts, $txtManageFilter, $btnManageClients, $btnDeleteSelected, $lblManageCount,
    $script:LvManageAccounts
))
$tabs.TabPages.Add($tabManage)

#--------------------------------------------
# TAB 6: Log Viewer
#--------------------------------------------
$tabLog         = New-Object System.Windows.Forms.TabPage
$tabLog.Text    = '  Log  '
$tabLog.Padding = New-Object System.Windows.Forms.Padding(0)

# Top bar panel - fixed height, stretches horizontally
$pnlLogBar          = New-Object System.Windows.Forms.Panel
$pnlLogBar.Dock     = [System.Windows.Forms.DockStyle]::Top
$pnlLogBar.Height   = 36
$pnlLogBar.BackColor= $COLOR_PANEL

$btnRefreshLog          = New-Button 'Refresh' 6 4 80 26
$btnOpenLogFolder       = New-Button 'Open Log Folder' 92 4 130 26
$lblLogPath             = New-Object System.Windows.Forms.Label
$lblLogPath.Location    = New-Object System.Drawing.Point(230, 8)
$lblLogPath.Size        = New-Object System.Drawing.Size(500, 18)
$lblLogPath.Font        = New-Object System.Drawing.Font('Segoe UI', 8)
$lblLogPath.ForeColor   = [System.Drawing.Color]::Gray
$lblLogPath.Anchor      = $AnchorTLR
$lblLogPath.Text        = $script:LogFile
$pnlLogBar.Controls.AddRange(@($btnRefreshLog, $btnOpenLogFolder, $lblLogPath))

$script:TxtLog            = New-Object System.Windows.Forms.RichTextBox
$script:TxtLog.Dock       = [System.Windows.Forms.DockStyle]::Fill
$script:TxtLog.Font       = New-Object System.Drawing.Font('Consolas', 8)
$script:TxtLog.ReadOnly   = $true
$script:TxtLog.BackColor  = [System.Drawing.Color]::FromArgb(20, 20, 20)
$script:TxtLog.ForeColor  = [System.Drawing.Color]::LightGray
$script:TxtLog.ScrollBars = 'Vertical'

# Add RichTextBox first so Dock=Fill fills remaining space after the top panel
$tabLog.Controls.Add($script:TxtLog)
$tabLog.Controls.Add($pnlLogBar)
$tabs.TabPages.Add($tabLog)

# ---- Status bar ----
$statusStrip              = New-Object System.Windows.Forms.StatusStrip
$script:StatusLabel       = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:StatusLabel.Text  = "Not connected.  |  Log: $($script:LogFile)"
$null = $statusStrip.Items.Add($script:StatusLabel)
$script:Form.Controls.Add($statusStrip)

#endregion

#region --- Log Viewer Helpers ---

function Refresh-LogViewer {
    if (Test-Path $script:LogFile) {
        $lines = Get-Content $script:LogFile
        $script:TxtLog.Clear()
        foreach ($line in $lines) {
            if     ($line -match '\[SUCCESS\]') { $script:TxtLog.SelectionColor = [System.Drawing.Color]::LightGreen }
            elseif ($line -match '\[ERROR  \]') { $script:TxtLog.SelectionColor = [System.Drawing.Color]::Tomato }
            elseif ($line -match '\[WARN   \]') { $script:TxtLog.SelectionColor = [System.Drawing.Color]::Gold }
            else                                { $script:TxtLog.SelectionColor = [System.Drawing.Color]::LightGray }
            $script:TxtLog.AppendText("$line`n")
        }
        $script:TxtLog.ScrollToCaret()
    }
}

# Auto-refresh log when switching to the Log tab
$tabs.Add_SelectedIndexChanged({
    if ($tabs.SelectedTab -eq $tabLog) { Refresh-LogViewer }
})

#endregion

#region --- Event Handlers ---

# Connect
$btnConnect.Add_Click({
    $orgId  = $txtOrgId.Text.Trim()
    $region = $cbRegion.SelectedItem.ToString()
    $token  = $txtToken.Text

    if ($token -eq '') {
        [System.Windows.Forms.MessageBox]::Show('Refresh Token is required.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ($orgId -eq '') {
        [System.Windows.Forms.MessageBox]::Show('Org ID is required.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    Set-Status 'Connecting...' 'Gray'
    $btnConnect.Enabled = $false
    Write-Log INFO "Connect button clicked. OrgId=$orgId Region=$region"

    $result = Invoke-Connect -OrgId $orgId -RefreshToken $token -Region $region
    $txtToken.Text = ''   # clear immediately after use

    if ($result -eq $true) {
        $script:ConnectIndicator.Text      = [char]0x2714 + ' Connected'
        $script:ConnectIndicator.ForeColor = [System.Drawing.Color]::Green

        $derivedScope      = "ref:nam:::iam:org:$orgId"
        $txtCScopeRef.Text = $derivedScope
        $txtAScopeRef.Text = $derivedScope
        Write-Log INFO "Scope Ref auto-set to '$derivedScope'"

        $roles = Get-AvailableRoles
        if ($roles) {
            Populate-RoleListBoxes -Roles $roles
            Set-Status "Connected to org $orgId ($region). $($roles.Count) roles loaded.  |  Log: $($script:LogFile)" 'Green'
        } else {
            Set-Status 'Connected but could not load roles. Check iam_admin permission.' 'DarkOrange'
        }
    } else {
        Set-Status $result 'Red'
        $script:ConnectIndicator.Text      = [char]0x2718 + ' Failed'
        $script:ConnectIndicator.ForeColor = [System.Drawing.Color]::Red
        $btnConnect.Enabled = $true
    }
})

# Create Account
$btnCreate.Add_Click({
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show('Please connect first.', 'Not Connected',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $name          = $txtCName.Text.Trim()
    $desc          = $txtCDesc.Text.Trim()
    $scope         = $txtCScopeRef.Text.Trim()
    $selectedRoles = @($script:LbCreateRoles.SelectedItems)

    if ($name -eq '') {
        [System.Windows.Forms.MessageBox]::Show('Account Name is required.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ($selectedRoles.Count -gt 0 -and $scope -eq '') {
        [System.Windows.Forms.MessageBox]::Show('Scope Ref is required when assigning roles.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    Write-Log INFO "Create Account button clicked. Name='$name' Description='$desc' Roles=$($selectedRoles -join ', ')"
    $script:LvCreateResult.Items.Clear()
    Set-Status "Creating service account '$name'..." 'Gray'

    try {
        $created = New-ServiceAccount -Name $name -Description $desc

        $fields = [ordered]@{
            Name          = Safe-Str $created.name
            ID            = Safe-Str $created.id
            'Subject Ref' = Safe-Str $created.ref
            'Created By'  = Safe-Str $created.createdBy
        }
        foreach ($key in $fields.Keys) {
            $row = New-Object System.Windows.Forms.ListViewItem($key)
            $null = $row.SubItems.Add($fields[$key])
            $null = $script:LvCreateResult.Items.Add($row)
        }
        foreach ($col in $script:LvCreateResult.Columns) { $col.Width = -2 }

        if ($selectedRoles.Count -gt 0) {
            Set-Status 'Account created. Assigning roles...' 'Gray'
            $roleResults = Invoke-AssignRoles -SubjectRef $created.ref `
                -Roles $selectedRoles -ScopeRef $scope
            $failed = @($roleResults | Where-Object { $_.Status -ne 'Assigned' })
            if ($failed.Count -eq 0) {
                Set-Status "Account created and $($selectedRoles.Count) role(s) assigned successfully." 'Green'
            } else {
                Set-Status "$($failed.Count) role assignment(s) failed. Account was still created." 'DarkOrange'
            }
        } else {
            Set-Status "Service account '$name' created successfully." 'Green'
        }

        $txtCName.Text = ''
        $txtCDesc.Text = ''
    }
    catch {
        Set-Status "Create failed: $_" 'Red'
        [System.Windows.Forms.MessageBox]::Show("Error: $_", 'Create Failed',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Assign Roles
$btnAssign.Add_Click({
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show('Please connect first.', 'Not Connected',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $subj          = $txtASubj.Text.Trim()
    $scope         = $txtAScopeRef.Text.Trim()
    $selectedRoles = @($script:LbAssignRoles.SelectedItems)

    if ($subj -eq '' -or $scope -eq '' -or $selectedRoles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Subject Ref, Scope Ref, and at least one Role are required.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    Write-Log INFO "Assign Roles button clicked. Subject='$subj' Roles=$($selectedRoles -join ', ')"
    $script:LvAssignResult.Items.Clear()
    Set-Status 'Assigning roles...' 'Gray'

    $results = Invoke-AssignRoles -SubjectRef $subj -Roles $selectedRoles -ScopeRef $scope

    foreach ($r in $results) {
        $row = New-Object System.Windows.Forms.ListViewItem((Safe-Str $r.Role))
        $null = $row.SubItems.Add((Safe-Str $r.Status))
        $row.ForeColor = if ($r.Status -eq 'Assigned') { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::Red }
        $null = $script:LvAssignResult.Items.Add($row)
    }
    foreach ($col in $script:LvAssignResult.Columns) { $col.Width = -2 }

    $failed = @($results | Where-Object { $_.Status -ne 'Assigned' })
    if ($failed.Count -eq 0) {
        Set-Status "All $($results.Count) role(s) assigned successfully." 'Green'
    } else {
        Set-Status "$($failed.Count) of $($results.Count) role assignment(s) failed." 'DarkOrange'
    }
})

# Enable revoke button when roles are selected
$script:LvViewResult.Add_SelectedIndexChanged({
    $btnRevokeRole.Enabled = ($script:LvViewResult.SelectedItems.Count -gt 0 -and $txtVSubj.Text.Trim() -ne '')
})

# Revoke Selected Role(s)
$btnRevokeRole.Add_Click({
    $subj          = $txtVSubj.Text.Trim()
    $selectedRoles = @($script:LvViewResult.SelectedItems)
    if ($subj -eq '' -or $selectedRoles.Count -eq 0) { return }

    $names   = ($selectedRoles | ForEach-Object { $_.Text }) -join "`n  - "
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Revoke $($selectedRoles.Count) role(s) from '$subj'?`n`n  - $names",
        'Confirm Revoke',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    Write-Log INFO "Revoke confirmed for $($selectedRoles.Count) role(s) from '$subj'."
    $scopeRef = $txtAScopeRef.Text.Trim()
    $revoked  = 0
    $failed   = 0

    foreach ($item in $selectedRoles) {
        try {
            Invoke-RevokeRole -SubjectRef $subj -RoleName $item.Text -ScopeRef $scopeRef
            $script:LvViewResult.Items.Remove($item)
            $revoked++
        }
        catch {
            $failed++
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to revoke '$($item.Text)': $_", 'Revoke Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }

    if ($failed -eq 0) {
        Set-Status "$revoked role(s) revoked successfully." 'Green'
    } else {
        Set-Status "$revoked revoked, $failed failed. Check log." 'DarkOrange'
    }
    $btnRevokeRole.Enabled = $false
})

# View Assigned Roles
$btnView.Add_Click({
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show('Please connect first.', 'Not Connected',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $subj = $txtVSubj.Text.Trim()
    if ($subj -eq '') {
        [System.Windows.Forms.MessageBox]::Show('Subject Ref is required.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    Write-Log INFO "Get Roles button clicked. Subject='$subj'"
    $script:LvViewResult.Items.Clear()
    Set-Status 'Retrieving assigned roles...' 'Gray'

    try {
        $roles = Get-AssignedRoles -SubjectRef $subj

        if (-not $roles -or $roles.Count -eq 0) {
            Set-Status 'No roles found for this subject ref.' 'DarkOrange'
            return
        }

        foreach ($r in $roles) {
            $row = New-Object System.Windows.Forms.ListViewItem((Safe-Str $r.role.name))
            $null = $row.SubItems.Add((Safe-Str $r.role.displayName))
            $null = $row.SubItems.Add((Safe-Str $r.role.category))
            $null = $row.SubItems.Add((Safe-Str $r.createdAt))
            $null = $script:LvViewResult.Items.Add($row)
        }
        foreach ($col in $script:LvViewResult.Columns) { $col.Width = -2 }

        Set-Status "$($roles.Count) role(s) found." 'Green'
    }
    catch {
        Set-Status "Error: $_" 'Red'
        [System.Windows.Forms.MessageBox]::Show("Error: $_", 'Request Failed',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Manage Accounts - filter placeholder behaviour
$txtManageFilter.Add_GotFocus({
    if ($txtManageFilter.Text -eq 'Filter by name...') {
        $txtManageFilter.Text      = ''
        $txtManageFilter.ForeColor = [System.Drawing.Color]::Black
    }
})
$txtManageFilter.Add_LostFocus({
    if ($txtManageFilter.Text -eq '') {
        $txtManageFilter.Text      = 'Filter by name...'
        $txtManageFilter.ForeColor = [System.Drawing.Color]::Gray
    }
})

# Filter list as user types
$txtManageFilter.Add_TextChanged({
    $filter = $txtManageFilter.Text.Trim()
    if ($filter -eq 'Filter by name...' -or $filter -eq '') { return }
    if (-not $script:AllServiceAccounts) { return }

    $script:LvManageAccounts.Items.Clear()
    $filtered = $script:AllServiceAccounts | Where-Object {
        (Safe-Str $_.name) -like "*$filter*"
    }
    foreach ($sa in $filtered) {
        $cc = if ($sa.PSObject.Properties['_clientCount']) { $sa._clientCount } else { $null }
        $row = New-Object System.Windows.Forms.ListViewItem((Safe-Str $sa.name))
        $null = $row.SubItems.Add((Format-CredCell $cc))
        $null = $row.SubItems.Add((Safe-Str $sa.id))
        $null = $row.SubItems.Add((Safe-Str $sa.ref))
        $null = $row.SubItems.Add((ConvertTo-GrantRef -IamRef (Safe-Str $sa.ref)))
        $null = $row.SubItems.Add((Safe-Str $sa.createdBy))
        $row.Tag = $sa
        $null = $script:LvManageAccounts.Items.Add($row)
    }
    foreach ($col in $script:LvManageAccounts.Columns) { $col.Width = -2 }
})

# Enable/disable Delete & Manage Clients buttons based on selection
$script:LvManageAccounts.Add_SelectedIndexChanged({
    $count = $script:LvManageAccounts.SelectedItems.Count
    $btnDeleteSelected.Enabled = ($count -gt 0)
    # Client management targets exactly one account
    $btnManageClients.Enabled  = ($count -eq 1)
})

# Manage clients (list / create / delete) for the selected service account
$btnManageClients.Add_Click({
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show('Please connect first.', 'Not Connected',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $selected = @($script:LvManageAccounts.SelectedItems)
    if ($selected.Count -ne 1) {
        [System.Windows.Forms.MessageBox]::Show('Select exactly one service account.', 'Validation',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $item = $selected[0]
    $sa   = $item.Tag
    $id   = Safe-Str $sa.id
    if ($id -eq '') { $id = $item.SubItems[2].Text }   # fall back to ID column
    $name = Safe-Str $sa.name
    if ($name -eq '') { $name = $item.Text }

    Write-Log INFO "Manage Clients opened. Account='$name' ID='$id'"
    Show-ClientManagerDialog -AccountName $name -ServiceAccountId $id

    # Refresh the credential-status cell to reflect any clients created/deleted.
    try {
        $n = @(Get-ServiceAccountClients -ServiceAccountId $id).Count
        $sa | Add-Member -NotePropertyName _clientCount -NotePropertyValue $n -Force
        $item.SubItems[1].Text = Format-CredCell $n
        Set-Status "Clients updated for '$name' ($n client(s))." 'Green'
    }
    catch {
        Write-Log WARN "Could not refresh credential status after Manage Clients: $(Get-ApiErrorMessage $_)"
    }
})

# Load Accounts
$btnLoadAccounts.Add_Click({
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show('Please connect first.', 'Not Connected',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    Write-Log INFO 'Load Accounts button clicked.'
    Set-Status 'Loading service accounts...' 'Gray'
    $script:LvManageAccounts.Items.Clear()
    $btnDeleteSelected.Enabled = $false

    try {
        $script:AllServiceAccounts = Get-ServiceAccounts

        if (-not $script:AllServiceAccounts -or $script:AllServiceAccounts.Count -eq 0) {
            Set-Status 'No service accounts found in this org.' 'DarkOrange'
            return
        }

        foreach ($sa in $script:AllServiceAccounts) {
            $row = New-Object System.Windows.Forms.ListViewItem((Safe-Str $sa.name))
            $null = $row.SubItems.Add('...')                                      # Credentials (filled below)
            $null = $row.SubItems.Add((Safe-Str $sa.id))
            $null = $row.SubItems.Add((Safe-Str $sa.ref))
            $null = $row.SubItems.Add((ConvertTo-GrantRef -IamRef (Safe-Str $sa.ref)))
            $null = $row.SubItems.Add((Safe-Str $sa.createdBy))
            $row.Tag = $sa
            $null = $script:LvManageAccounts.Items.Add($row)
        }
        $lblManageCount.Text = "$($script:AllServiceAccounts.Count) account(s) loaded."

        # Credential status: the SA object carries no client indicator, so query each
        # account's clients separately. Defensive - if the clients endpoint errors,
        # mark unknown ('?') and stop probing so Load still succeeds.
        $total = $script:LvManageAccounts.Items.Count
        $credCheckFailed = $false
        for ($i = 0; $i -lt $total; $i++) {
            $r      = $script:LvManageAccounts.Items[$i]
            $row_sa = $r.Tag
            $sid    = Safe-Str $row_sa.id
            if ($credCheckFailed -or $sid -eq '') {
                $row_sa | Add-Member -NotePropertyName _clientCount -NotePropertyValue $null -Force
                $r.SubItems[1].Text = Format-CredCell $null
                continue
            }
            Set-Status "Checking credential status ($($i + 1)/$total)..." 'Gray'
            try {
                $clients = Get-ServiceAccountClients -ServiceAccountId $sid
                $n = @($clients).Count
                $row_sa | Add-Member -NotePropertyName _clientCount -NotePropertyValue $n -Force
                $r.SubItems[1].Text = Format-CredCell $n
            }
            catch {
                $credCheckFailed = $true
                $row_sa | Add-Member -NotePropertyName _clientCount -NotePropertyValue $null -Force
                $r.SubItems[1].Text = Format-CredCell $null
                Write-Log WARN "Credential status check failed (clients endpoint): $(Get-ApiErrorMessage $_)"
            }
        }

        foreach ($col in $script:LvManageAccounts.Columns) { $col.Width = -2 }

        if ($credCheckFailed) {
            Set-Status "$($script:AllServiceAccounts.Count) account(s) loaded. Credential status unavailable - see Log." 'DarkOrange'
        } else {
            Set-Status "$($script:AllServiceAccounts.Count) service account(s) loaded." 'Green'
        }
    }
    catch {
        Set-Status "Failed to load accounts: $_" 'Red'
        [System.Windows.Forms.MessageBox]::Show("Error: $_", 'Load Failed',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Delete Selected
$btnDeleteSelected.Add_Click({
    $selected = @($script:LvManageAccounts.SelectedItems)
    if ($selected.Count -eq 0) { return }

    $names = ($selected | ForEach-Object { $_.Text }) -join "`n  - "
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Permanently delete $($selected.Count) service account(s)?`n`n  - $names`n`nThis cannot be undone.",
        'Confirm Delete',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log INFO 'Delete cancelled by user.'
        return
    }

    Write-Log INFO "Delete confirmed for $($selected.Count) account(s)."
    $deleted = 0
    $failed  = 0

    foreach ($item in $selected) {
        $sa = $item.Tag
        $id   = Safe-Str $sa.id
        $name = Safe-Str $sa.name

        # Fall back to text columns if Tag properties are empty (field name mismatch)
        if ($id -eq '') { $id = $item.SubItems[2].Text }

        try {
            Remove-ServiceAccount -AccountId $id -AccountName $name
            $script:LvManageAccounts.Items.Remove($item)
            $deleted++
        }
        catch {
            $failed++
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to delete '$name': $_", 'Delete Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }

    # Refresh cached list to keep it in sync with remaining displayed rows
    $remainingRefs = @($script:LvManageAccounts.Items | ForEach-Object { $_.Tag.ref })
    $script:AllServiceAccounts = $script:AllServiceAccounts | Where-Object { $remainingRefs -contains $_.ref }

    if ($failed -eq 0) {
        Set-Status "$deleted account(s) deleted successfully." 'Green'
    } else {
        Set-Status "$deleted deleted, $failed failed. Check log for details." 'DarkOrange'
    }
    $btnDeleteSelected.Enabled = $false
})

# Manage Accounts context menu
$ctxManage.Add_Opening({
    $hasSelection = ($script:LvManageAccounts.SelectedItems.Count -gt 0)
    $mnuCopyRef.Enabled    = $hasSelection
    $mnuCopyApiRef.Enabled = $hasSelection
    $mnuCopyId.Enabled     = $hasSelection
    $mnuCopyName.Enabled   = $hasSelection
})

$mnuCopyRef.Add_Click({
    $item = $script:LvManageAccounts.SelectedItems[0]
    if ($item -and $item.Tag) {
        $val = Safe-Str $item.Tag.ref
        Set-Clipboard $val
        Set-Status "Subject Ref (iam#) copied: $val" 'Green'
        Write-Log INFO "Copied Subject Ref (iam#) to clipboard: $val"
    }
})

$mnuCopyApiRef.Add_Click({
    $item = $script:LvManageAccounts.SelectedItems[0]
    if ($item -and $item.Tag) {
        $val = ConvertTo-GrantRef -IamRef (Safe-Str $item.Tag.ref)
        Set-Clipboard $val
        Set-Status "Subject Ref (API) copied: $val" 'Green'
        Write-Log INFO "Copied Subject Ref (API) to clipboard: $val"
    }
})

$mnuCopyId.Add_Click({
    $item = $script:LvManageAccounts.SelectedItems[0]
    if ($item -and $item.Tag) {
        $val = Safe-Str $item.Tag.id
        Set-Clipboard $val
        Set-Status "ID copied: $val" 'Green'
        Write-Log INFO "Copied ID to clipboard: $val"
    }
})

$mnuCopyName.Add_Click({
    $item = $script:LvManageAccounts.SelectedItems[0]
    if ($item -and $item.Tag) {
        $val = Safe-Str $item.Tag.name
        Set-Clipboard $val
        Set-Status "Name copied: $val" 'Green'
        Write-Log INFO "Copied Name to clipboard: $val"
    }
})

# Log tab buttons
$btnRefreshLog.Add_Click({ Refresh-LogViewer })
$btnOpenLogFolder.Add_Click({ Start-Process explorer.exe $script:LogFolder })

# Clear tokens on close
$script:Form.Add_FormClosing({
    Write-Log INFO 'Session ended. Form closed.'
    $script:AccessToken = $null
    $script:Headers     = $null
    [System.GC]::Collect()
})

#endregion

# Launch
[System.Windows.Forms.Application]::Run($script:Form)
