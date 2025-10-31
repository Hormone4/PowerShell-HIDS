<#
.SYNOPSIS
    Host-based Intrusion Detection System (HIDS) - File Integrity Monitor
.DESCRIPTION
    Monitors file integrity across multiple machines by comparing file hashes
    and sends email alerts when changes are detected.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Configure', 'Start', 'Stop', 'Status')]
    [string]$Action = 'Configure'
)

# Configuration file path
$ConfigFile = "$PSScriptRoot\HIDS-Config.json"
$HashDBFile = "$PSScriptRoot\HIDS-HashDB.json"
$LogFile = "$PSScriptRoot\HIDS-Changes.log"
$JobName = "HIDS-Monitor"

#region Functions

function Show-Menu {
    #Clear-Host
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "  File Integrity Monitor (HIDS)" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Configure Monitoring Settings"
    Write-Host "2. Configure Email Alerts"
    Write-Host "3. Add Monitored Paths"
    Write-Host "4. Remove Monitored Paths"
    Write-Host "5. View Current Configuration"
    Write-Host "6. Start Monitoring"
    Write-Host "7. Stop Monitoring"
    Write-Host "8. View Monitoring Status"
    Write-Host "9. Exit"
    Write-Host ""
}

function Initialize-Config {
    if (-not (Test-Path $ConfigFile)) {
        $defaultConfig = @{
            MonitoredHosts = @()
            MonitoredPaths = @()
            EmailSettings = @{
                SmtpServer = ""
                SmtpPort = 587
                From = ""
                To = @()
                UseSSL = $true
                Credentials = @{
                    Username = ""
                    PasswordEncrypted = ""
                }
            }
            CheckIntervalSeconds = 300
        }
        $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile
    }
    return Get-Content $ConfigFile | ConvertFrom-Json
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile
    Write-Host "Configuration saved successfully." -ForegroundColor Green
}

function Configure-MonitoringSettings {
    $config = Initialize-Config
    
    Write-Host "`nConfigure Monitoring Settings" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Yellow
    
    # Configure hosts
    $hostsInput = Read-Host "`nEnter IP addresses or hostnames (comma-separated)"
    if ($hostsInput) {
        $config.MonitoredHosts = $hostsInput -split ',' | ForEach-Object { $_.Trim() }
    }
    
    # Configure check interval
    $interval = Read-Host "Enter check interval in seconds (default: 300)"
    if ($interval -and $interval -match '^\d+$') {
        $config.CheckIntervalSeconds = [int]$interval
    }
    
    Save-Config $config
}

function Configure-EmailSettings {
    $config = Initialize-Config
    
    Write-Host "`nConfigure Email Alert Settings" -ForegroundColor Yellow
    Write-Host "===============================" -ForegroundColor Yellow
    
    $smtpServer = Read-Host "Enter SMTP server"
    if ($smtpServer) { $config.EmailSettings.SmtpServer = $smtpServer }
    
    $smtpPort = Read-Host "Enter SMTP port (default: 587)"
    if ($smtpPort -match '^\d+$') { $config.EmailSettings.SmtpPort = [int]$smtpPort }
    
    $from = Read-Host "Enter sender email address"
    if ($from) { $config.EmailSettings.From = $from }
    
    $to = Read-Host "Enter recipient email addresses (comma-separated)"
    if ($to) { $config.EmailSettings.To = $to -split ',' | ForEach-Object { $_.Trim() } }
    
    $useSSL = Read-Host "Use SSL? (Y/N, default: Y)"
    $config.EmailSettings.UseSSL = ($useSSL -ne 'N')
    
    $username = Read-Host "Enter SMTP username"
    if ($username) { $config.EmailSettings.Credentials.Username = $username }
    
    $password = Read-Host "Enter SMTP password" -AsSecureString
    if ($password.Length -gt 0) {
        $config.EmailSettings.Credentials.PasswordEncrypted = ConvertFrom-SecureString $password
    }
    
    Save-Config $config
}

function Add-MonitoredPaths {
    $config = Initialize-Config
    
    Write-Host "`nAdd Monitored Paths" -ForegroundColor Yellow
    Write-Host "===================" -ForegroundColor Yellow
    
    do {
        $host_input = Read-Host "`nEnter hostname/IP (or press Enter to finish)"
        if (-not $host_input) { break }
        
        $path = Read-Host "Enter path (not file) to monitor on $host_input"
        if (-not $path) { continue }
        
        $recursive = Read-Host "Monitor recursively? (Y/N, default: N)"
        
        $pathObj = @{
            Host = $host_input
            Path = $path
            Recursive = ($recursive -eq 'Y')
        }
        
        $config.MonitoredPaths += $pathObj
        Write-Host "Added: $($pathObj.Host):$($pathObj.Path)" -ForegroundColor Green
        
    } while ($true)
    
    Save-Config $config
}

function Remove-MonitoredPaths {
    $config = Initialize-Config
    
    if ($config.MonitoredPaths.Count -eq 0) {
        Write-Host "No monitored paths configured." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nCurrent Monitored Paths:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $config.MonitoredPaths.Count; $i++) {
        $path = $config.MonitoredPaths[$i]
        Write-Host "$($i+1). $($path.Host):$($path.Path) (Recursive: $($path.Recursive))"
    }
    
    $index = Read-Host "`nEnter number to remove (or press Enter to cancel)"
    if ($index -match '^\d+$') {
        $idx = [int]$index - 1
        if ($idx -ge 0 -and $idx -lt $config.MonitoredPaths.Count) {
            $removed = $config.MonitoredPaths[$idx]
            $config.MonitoredPaths = @($config.MonitoredPaths | Where-Object { $_ -ne $removed })
            Write-Host "Removed: $($removed.Host):$($removed.Path)" -ForegroundColor Green
            Save-Config $config
        }
    }
}

function Show-Configuration {
    $config = Initialize-Config
    
    Write-Host "`nCurrent Configuration" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host "`nMonitored Hosts:" -ForegroundColor Yellow
    $config.MonitoredHosts | ForEach-Object { Write-Host "  - $_" }
    
    Write-Host "`nMonitored Paths:" -ForegroundColor Yellow
    $config.MonitoredPaths | ForEach-Object {
        Write-Host "  - $($_.Host):$($_.Path) (Recursive: $($_.Recursive))"
    }
    
    Write-Host "`nEmail Settings:" -ForegroundColor Yellow
    Write-Host "  SMTP Server: $($config.EmailSettings.SmtpServer):$($config.EmailSettings.SmtpPort)"
    Write-Host "  From: $($config.EmailSettings.From)"
    Write-Host "  To: $($config.EmailSettings.To -join ', ')"
    Write-Host "  SSL: $($config.EmailSettings.UseSSL)"
    
    Write-Host "`nCheck Interval: $($config.CheckIntervalSeconds) seconds" -ForegroundColor Yellow
}

function Get-FileHashesFromRemote {
    param(
        [string]$ComputerName,
        [string]$Path,
        [bool]$Recursive
    )
    
    try {
        $scriptBlock = {
            param($TargetPath, $IsRecursive)
            
            if (Test-Path $TargetPath) {
                $files = if ($IsRecursive) {
                    Get-ChildItem -Path $TargetPath -File -Recurse -ErrorAction SilentlyContinue
                } else {
                    Get-ChildItem -Path $TargetPath -File -ErrorAction SilentlyContinue
                }
                
                $files | ForEach-Object {
                    @{
                        Path = $_.FullName
                        Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
                        LastModified = $_.LastWriteTime
                    }
                }
            }
        }
        
        if ($ComputerName -eq "localhost" -or $ComputerName -eq $env:COMPUTERNAME) {
            & $scriptBlock -TargetPath $Path -IsRecursive $Recursive
        } else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $Path, $Recursive
        }
    }
    catch {
        Write-Warning "Failed to get hashes from ${ComputerName}: $_"
        return @()
    }
}

function Send-AlertEmail {
    param(
        [string]$Subject,
        [string]$Body,
        $Config
    )
    
    try {
        $emailParams = @{
            SmtpServer = $Config.EmailSettings.SmtpServer
            Port = $Config.EmailSettings.SmtpPort
            From = $Config.EmailSettings.From
            To = $Config.EmailSettings.To
            Subject = $Subject
            Body = $Body
            BodyAsHtml = $true
            UseSsl = $Config.EmailSettings.UseSSL
        }
        
        if ($Config.EmailSettings.Credentials.Username -and $Config.EmailSettings.Credentials.PasswordEncrypted) {
            $securePassword = ConvertTo-SecureString $Config.EmailSettings.Credentials.PasswordEncrypted
            $credential = New-Object System.Management.Automation.PSCredential(
                $Config.EmailSettings.Credentials.Username,
                $securePassword
            )
            $emailParams.Credential = $credential
        }
        
        Send-MailMessage @emailParams
        Write-Host "Alert email sent successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to send email: $_"
    }
}

function Start-Monitoring {
    $config = Initialize-Config
    
    if ($config.MonitoredPaths.Count -eq 0) {
        Write-Host "No paths configured for monitoring. Please configure first." -ForegroundColor Red
        return
    }
    
    # Check if already running
    $existingJob = Get-Job -Name $JobName -ErrorAction SilentlyContinue
    if ($existingJob) {
        Write-Host "Monitoring is already running." -ForegroundColor Yellow
        return
    }
    
    # Initialize hash database
    Write-Host "Building initial hash database..." -ForegroundColor Yellow
    $hashDB = @{}
    
    foreach ($monPath in $config.MonitoredPaths) {
        $hashes = Get-FileHashesFromRemote -ComputerName $monPath.Host -Path $monPath.Path -Recursive $monPath.Recursive
        $key = "$($monPath.Host):$($monPath.Path)"
        # Ensure hashes is always an array
        $hashDB[$key] = @($hashes)
    }
    
    $hashDB | ConvertTo-Json -Depth 10 | Set-Content $HashDBFile
    Write-Host "Initial hash database created." -ForegroundColor Green
    
    # Start monitoring job
    $job = Start-Job -Name $JobName -ScriptBlock {
        param($ConfigPath, $HashDBPath, $LogFilePath, $ScriptRoot)
        
        while ($true) {
            $config = Get-Content $ConfigPath | ConvertFrom-Json
            $hashDB = Get-Content $HashDBPath | ConvertFrom-Json
            $changes = @()
            
            foreach ($monPath in $config.MonitoredPaths) {
                $key = "$($monPath.Host):$($monPath.Path)"
                
                # Get current hashes
                $currentHashes = & {
                    param($ComputerName, $Path, $Recursive)
                    
                    $scriptBlock = {
                        param($TargetPath, $IsRecursive)
                        
                        if (Test-Path $TargetPath) {
                            $files = if ($IsRecursive) {
                                Get-ChildItem -Path $TargetPath -File -Recurse -ErrorAction SilentlyContinue
                            } else {
                                Get-ChildItem -Path $TargetPath -File -ErrorAction SilentlyContinue
                            }
                            
                            $files | ForEach-Object {
                                @{
                                    Path = $_.FullName
                                    Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
                                    LastModified = $_.LastWriteTime
                                }
                            }
                        }
                    }
                    
                    try {
                        if ($ComputerName -eq "localhost" -or $ComputerName -eq $env:COMPUTERNAME) {
                            & $scriptBlock -TargetPath $Path -IsRecursive $Recursive
                        } else {
                            Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $Path, $Recursive
                        }
                    }
                    catch {
                        @()
                    }
                } -ComputerName $monPath.Host -Path $monPath.Path -Recursive $monPath.Recursive
                
                # Compare hashes
                $oldHashes = @($hashDB.$key)
                
                if ($oldHashes -and $oldHashes.Count -gt 0 -and $oldHashes[0]) {
                    $oldHashDict = @{}
                    $oldHashes | ForEach-Object { 
                        if ($_ -and $_.Path) {
                            $oldHashDict[$_.Path] = $_
                        }
                    }
                    
                    foreach ($current in $currentHashes) {
                        if (-not $oldHashDict.ContainsKey($current.Path)) {
                            $changes += @{ Type = "New"; File = $current.Path; Host = $monPath.Host }
                        }
                        elseif ($oldHashDict[$current.Path].Hash -ne $current.Hash) {
                            $changes += @{ Type = "Modified"; File = $current.Path; Host = $monPath.Host }
                        }
                    }
                    
                    $currentHashDict = @{}
                    $currentHashes | ForEach-Object { $currentHashDict[$_.Path] = $_ }
                    
                    foreach ($old in $oldHashes) {
                        if ($old -and $old.Path -and -not $currentHashDict.ContainsKey($old.Path)) {
                            $changes += @{ Type = "Deleted"; File = $old.Path; Host = $monPath.Host }
                        }
                    }
                }
                
                # Update hash database (convert PSCustomObject to hashtable for updates)
                if ($hashDB -is [PSCustomObject]) {
                    $hashDBTemp = @{}
                    $hashDB.PSObject.Properties | ForEach-Object { $hashDBTemp[$_.Name] = $_.Value }
                    $hashDBTemp[$key] = @($currentHashes)
                    $hashDB = $hashDBTemp
                } else {
                    $hashDB[$key] = @($currentHashes)
                }
            }
            
            # Save updated hash database
            $hashDB | ConvertTo-Json -Depth 10 | Set-Content $HashDBPath
            
            # Send alert if changes detected
            if ($changes.Count -gt 0) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                # Log changes to file
                $logEntry = "`n=== File Integrity Alert - $timestamp ===`n"
                foreach ($change in $changes) {
                    $logEntry += "[$($change.Type)] $($change.File) on $($change.Host)`n"
                }
                Add-Content -Path $LogFilePath -Value $logEntry
                
                # Prepare email body
                $body = "<h2>File Integrity Alert</h2><p>The following changes were detected:</p><ul>"
                foreach ($change in $changes) {
                    $body += "<li><strong>$($change.Type)</strong>: $($change.File) on $($change.Host)</li>"
                }
                $body += "</ul><p>Time: $(Get-Date)</p>"
                
                # Save alert data for email sending (delegated to main script)
                $alertData = @{
                    Subject = "HIDS Alert: File Integrity Changes Detected"
                    Body = $body
                    Changes = $changes
                    Timestamp = $timestamp
                }
                $alertData | ConvertTo-Json -Depth 10 | Out-File "$ScriptRoot\HIDS-Alert.json"
            }
            
            Start-Sleep -Seconds $config.CheckIntervalSeconds
        }
    } -ArgumentList $ConfigFile, $HashDBFile, $LogFile, $PSScriptRoot
    
    Write-Host "Monitoring started in background (Job ID: $($job.Id))." -ForegroundColor Green
    Write-Host "Use 'Stop Monitoring' to stop the service." -ForegroundColor Cyan
}

function Stop-Monitoring {
    $job = Get-Job -Name $JobName -ErrorAction SilentlyContinue
    
    if ($job) {
        Stop-Job -Name $JobName
        Remove-Job -Name $JobName
        Write-Host "Monitoring stopped." -ForegroundColor Green
    }
    else {
        Write-Host "Monitoring is not running." -ForegroundColor Yellow
    }
}

function Show-MonitoringStatus {
    $job = Get-Job -Name $JobName -ErrorAction SilentlyContinue
    
    Write-Host "`nMonitoring Status" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    if ($job) {
        Write-Host "Status: Running" -ForegroundColor Green
        Write-Host "Job ID: $($job.Id)"
        Write-Host "State: $($job.State)"
        
        # Check for alerts and send email
        $alertFile = "$PSScriptRoot\HIDS-Alert.json"
        if (Test-Path $alertFile) {
            $alertData = Get-Content $alertFile | ConvertFrom-Json
            Write-Host "`nLast Alert:" -ForegroundColor Yellow
            
            if ($alertData.Changes) {
                $alertData.Changes | ForEach-Object {
                    Write-Host "  [$($_.Type)] $($_.File) on $($_.Host)" -ForegroundColor Red
                }
                
                # Send email alert
                $config = Initialize-Config
                if ($config.EmailSettings.SmtpServer) {
                    Write-Host "`nSending email alert..." -ForegroundColor Yellow
                    Send-AlertEmail -Subject $alertData.Subject -Body $alertData.Body -Config $config
                    
                    # Remove alert file after processing
                    Remove-Item $alertFile -ErrorAction SilentlyContinue
                }
            }
        }
    }
    else {
        Write-Host "Status: Not Running" -ForegroundColor Red
    }
}

#endregion

# Main execution
switch ($Action) {
    'Configure' {
        do {
            Show-Menu
            $choice = Read-Host "Select an option"
            
            switch ($choice) {
                '1' { Configure-MonitoringSettings }
                '2' { Configure-EmailSettings }
                '3' { Add-MonitoredPaths }
                '4' { Remove-MonitoredPaths }
                '5' { Show-Configuration }
                '6' { Start-Monitoring }
                '7' { Stop-Monitoring }
                '8' { Show-MonitoringStatus }
                '9' { exit }
            }
            
            if ($choice -ne '9') {
                Write-Host "`n`n"
                #Write-Host "`nPress any key to continue..."
                #$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        } while ($choice -ne '9')
    }
    'Start' { Start-Monitoring }
    'Stop' { Stop-Monitoring }
    'Status' { Show-MonitoringStatus }
}

Write-Host "`n`n"