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
        try {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body   = $reader.ReadToEnd()
            $reader.Close()
            $parsed = $body | ConvertFrom-Json
            if ($parsed.message) { return "HTTP $code - $($parsed.message)" }
        } catch { }
        return "HTTP $code - $($ErrorRecord.Exception.Message)"
    }
    return $ErrorRecord.Exception.Message
}

# Safely coerce a value to string — ListViewItem.SubItems.Add() throws on $null
function Safe-Str {
    param ($Value)
    if ($null -eq $Value) { return '' }
    return [string]$Value
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

function Get-AvailableRoles {
    $uri = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/roles"
    Write-Log INFO "GET  | $uri"
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
        Write-Log SUCCESS "GET  | Roles retrieved: $($resp.values.Count) roles."
        return $resp.values
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
        $resp = Invoke-RestMethod -Method Post -Uri $uri `
            -Headers $script:Headers `
            -Body ($body | ConvertTo-Json -Depth 3)
        Write-Log SUCCESS "POST | Service account created. ID=$($resp.id) SubjectRef=$($resp.subjectRef)"
        return $resp
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "POST | Failed to create service account '$Name': $msg"
        throw $msg
    }
}

function Invoke-AssignRoles {
    param ([string]$SubjectRef, [string[]]$Roles, [string]$ScopeRef)

    $uri     = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/access-rules/grant"
    $results = @()

    foreach ($role in $Roles) {
        $payload = @{
            role    = @{ name = $role }
            scope   = @{ ref  = $ScopeRef }
            subject = @{ ref  = $SubjectRef }
        } | ConvertTo-Json -Depth 5

        Write-Log INFO "PUT  | $uri | Role='$role' Subject='$SubjectRef' Scope='$ScopeRef'"
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

function Get-AssignedRoles {
    param ([string]$SubjectRef)

    $filter = [System.Uri]::EscapeDataString("subjectRef eq '$SubjectRef'")
    $uri    = "$($script:ApiBase)/iam/v1/orgs/$($script:OrgId)/access-rules?filter=$filter&view=extended"

    Write-Log INFO "GET  | $uri"
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers
        Write-Log SUCCESS "GET  | $($resp.values.Count) role(s) found for '$SubjectRef'."
        return $resp.values
    }
    catch {
        $msg = Get-ApiErrorMessage $_
        Write-Log ERROR "GET  | Failed to retrieve roles for '$SubjectRef': $msg"
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

    $script:LvAvailableRoles.Items.Clear()
    foreach ($r in ($Roles | Sort-Object name)) {
        $item = New-Object System.Windows.Forms.ListViewItem((Safe-Str $r.name))
        $null = $item.SubItems.Add((Safe-Str $r.displayName))
        $null = $item.SubItems.Add((Safe-Str $r.category))
        $null = $item.SubItems.Add((Safe-Str $r.description))
        $null = $script:LvAvailableRoles.Items.Add($item)
    }
    foreach ($col in $script:LvAvailableRoles.Columns) { $col.Width = -2 }
}

#endregion

#region --- Build Form ---

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text            = 'Flexera One — Service Account Manager'
$script:Form.Size            = New-Object System.Drawing.Size(780, 700)
$script:Form.StartPosition   = 'CenterScreen'
$script:Form.FormBorderStyle = 'FixedSingle'
$script:Form.MaximizeBox     = $false
$script:Form.BackColor       = $COLOR_PANEL
$script:Form.Font            = $FONT_LABEL

# ---- Connection GroupBox ----
$gbConn          = New-Object System.Windows.Forms.GroupBox
$gbConn.Text     = 'Connection'
$gbConn.Location = New-Object System.Drawing.Point(10, 8)
$gbConn.Size     = New-Object System.Drawing.Size(744, 80)
$gbConn.Font     = $FONT_BOLD

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
$script:LbCreateRoles.Font           = $FONT_LABEL
$null = $script:LbCreateRoles.Items.Add('Connect first to load available roles')

$btnCreate             = New-Button 'Create Account' 125 328 140
$script:LvCreateResult = New-ListView 10 368 710 120 @('Field','Value')

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
$script:LbAssignRoles.Font          = $FONT_LABEL
$null = $script:LbAssignRoles.Items.Add('Connect first to load available roles')

$btnAssign             = New-Button 'Assign Roles' 125 306 120
$script:LvAssignResult = New-ListView 10 344 710 140 @('Role','Status')

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

$lblVSubj            = New-Label 'Subject Ref: *' 10 16 110
$txtVSubj            = New-TextBox 125 14 400
$btnView             = New-Button 'Get Roles' 540 12 110
$script:LvViewResult = New-ListView 10 52 710 436 @('Role Name','Display Name','Category','Assigned At')

$tabView.Controls.AddRange(@($lblVSubj, $txtVSubj, $btnView, $script:LvViewResult))
$tabs.TabPages.Add($tabView)

#--------------------------------------------
# TAB 4: Browse Available Roles
#--------------------------------------------
$tabBrowse      = New-Object System.Windows.Forms.TabPage
$tabBrowse.Text = '  Available Roles  '

$lblBrowseHint          = New-Object System.Windows.Forms.Label
$lblBrowseHint.Text     = 'Connect to populate. All roles available in your org are listed here.'
$lblBrowseHint.Location = New-Object System.Drawing.Point(10, 10)
$lblBrowseHint.Size     = New-Object System.Drawing.Size(700, 18)
$lblBrowseHint.Font     = New-Object System.Drawing.Font('Segoe UI', 8)
$lblBrowseHint.ForeColor= [System.Drawing.Color]::Gray

$script:LvAvailableRoles = New-ListView 10 32 710 460 @('Role Name','Display Name','Category','Description')

$tabBrowse.Controls.AddRange(@($lblBrowseHint, $script:LvAvailableRoles))
$tabs.TabPages.Add($tabBrowse)

#--------------------------------------------
# TAB 5: Log Viewer
#--------------------------------------------
$tabLog      = New-Object System.Windows.Forms.TabPage
$tabLog.Text = '  Log  '

$btnRefreshLog          = New-Button 'Refresh' 10 10 80 26
$btnOpenLogFolder       = New-Button 'Open Log Folder' 100 10 130 26
$lblLogPath             = New-Object System.Windows.Forms.Label
$lblLogPath.Location    = New-Object System.Drawing.Point(240, 14)
$lblLogPath.Size        = New-Object System.Drawing.Size(490, 18)
$lblLogPath.Font        = New-Object System.Drawing.Font('Segoe UI', 8)
$lblLogPath.ForeColor   = [System.Drawing.Color]::Gray
$lblLogPath.Text        = $script:LogFile

$script:TxtLog          = New-Object System.Windows.Forms.RichTextBox
$script:TxtLog.Location = New-Object System.Drawing.Point(10, 44)
$script:TxtLog.Size     = New-Object System.Drawing.Size(710, 448)
$script:TxtLog.Font     = New-Object System.Drawing.Font('Consolas', 8)
$script:TxtLog.ReadOnly = $true
$script:TxtLog.BackColor= [System.Drawing.Color]::FromArgb(20, 20, 20)
$script:TxtLog.ForeColor= [System.Drawing.Color]::LightGray
$script:TxtLog.ScrollBars = 'Vertical'

$tabLog.Controls.AddRange(@($btnRefreshLog, $btnOpenLogFolder, $lblLogPath, $script:TxtLog))
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

        $derivedScope      = "global/orgs/$orgId"
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
            'Subject Ref' = Safe-Str $created.subjectRef
            'Created At'  = Safe-Str $created.createdAt
        }
        foreach ($key in $fields.Keys) {
            $row = New-Object System.Windows.Forms.ListViewItem($key)
            $null = $row.SubItems.Add($fields[$key])
            $null = $script:LvCreateResult.Items.Add($row)
        }
        foreach ($col in $script:LvCreateResult.Columns) { $col.Width = -2 }

        if ($selectedRoles.Count -gt 0) {
            Set-Status 'Account created. Assigning roles...' 'Gray'
            $roleResults = Invoke-AssignRoles -SubjectRef $created.subjectRef `
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
