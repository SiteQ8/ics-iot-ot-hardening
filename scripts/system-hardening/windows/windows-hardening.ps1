# Windows ICS System Hardening Script
# Author: Ali AlEnezi
# Github: https://github.com/SiteQ8/ics-iot-ot-hardening
# Version: 1.0.0
# 🔎 Purpose
# Strengthen Windows security for ICS/SCADA use.
# Reduce attack surface by disabling unnecessary features/services.
# Enforce stricter security policies.
# Generate logs and compliance reports for auditing.
# Description: Hardens Windows systems for ICS/SCADA environments

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = ".\config\windows-hardening-config.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = ".\logs\hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry
    if (!(Test-Path (Split-Path $LogFile))) {
        New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $logEntry
}

# Check if running as administrator
function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Disable unnecessary services for ICS environments
function Disable-UnnecessaryServices {
    Write-Log "Disabling unnecessary services for ICS environment"
    
    $servicesToDisable = @(
        "Spooler",                  # Print Spooler (rarely needed in ICS)
        "Fax",                      # Fax Service
        "WSearch",                  # Windows Search
        "HomeGroupListener",        # HomeGroup Listener
        "HomeGroupProvider",        # HomeGroup Provider
        "WbioSrvc",                # Windows Biometric Service
        "XblAuthManager",          # Xbox Live Auth Manager
        "XblGameSave",             # Xbox Live Game Save
        "TabletInputService",      # Touch Keyboard and Handwriting Panel
        "RemoteRegistry"           # Remote Registry (security risk)
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if (!$DryRun) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled
                }
                Write-Log "Disabled service: $service"
            }
        }
        catch {
            Write-Log "Failed to disable service $service`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Configure Windows Firewall for ICS environment
function Configure-WindowsFirewall {
    Write-Log "Configuring Windows Firewall for ICS environment"
    
    try {
        if (!$DryRun) {
            # Enable Windows Firewall for all profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
            
            # Set default policies
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
            
            # Log dropped packets
            Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked True -LogMaxSizeKilobytes 4096
        }
        
        # Common ICS ports to allow
        $icsRules = @(
            @{Name="Modbus-TCP-In"; Port=502; Direction="Inbound"; Description="Modbus TCP"},
            @{Name="DNP3-TCP-In"; Port=20000; Direction="Inbound"; Description="DNP3 TCP"},
            @{Name="IEC61850-MMS-In"; Port=102; Direction="Inbound"; Description="IEC 61850 MMS"},
            @{Name="OPC-DA-In"; Port=135; Direction="Inbound"; Description="OPC DA"},
            @{Name="OPC-UA-In"; Port=4840; Direction="Inbound"; Description="OPC UA"},
            @{Name="EtherNetIP-In"; Port=44818; Direction="Inbound"; Description="EtherNet/IP"}
        )
        
        foreach ($rule in $icsRules) {
            if (!$DryRun) {
                $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
                if (!$existingRule) {
                    New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Protocol TCP -LocalPort $rule.Port -Action Allow -Description $rule.Description
                }
            }
            Write-Log "Configured firewall rule: $($rule.Name)"
        }
        
        Write-Log "Windows Firewall configuration completed"
    }
    catch {
        Write-Log "Failed to configure Windows Firewall: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Harden user account policies
function Set-AccountPolicies {
    Write-Log "Configuring account security policies"
    
    try {
        if (!$DryRun) {
            # Account lockout policy
            secedit /configure /cfg @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 12
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 1
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
"@
        }
        Write-Log "Account policies configured"
    }
    catch {
        Write-Log "Failed to configure account policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Configure audit policies
function Set-AuditPolicies {
    Write-Log "Configuring audit policies"
    
    $auditPolicies = @(
        "Logon/Logoff",
        "Account Management", 
        "System Events",
        "Policy Changes",
        "Privilege Use",
        "Object Access"
    )
    
    foreach ($policy in $auditPolicies) {
        try {
            if (!$DryRun) {
                auditpol /set /category:"$policy" /success:enable /failure:enable
            }
            Write-Log "Enabled audit policy: $policy"
        }
        catch {
            Write-Log "Failed to set audit policy $policy`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Secure registry settings
function Set-RegistrySettings {
    Write-Log "Applying security registry settings"
    
    $registrySettings = @(
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RestrictAnonymous"
            Value = 1
            Type = "DWORD"
            Description = "Restrict anonymous access"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "NoLMHash"
            Value = 1
            Type = "DWORD"
            Description = "Disable LM hash storage"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Name = "NullSessionShares"
            Value = @()
            Type = "MultiString"
            Description = "Remove null session shares"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            Name = "ProtectionMode"
            Value = 1
            Type = "DWORD"
            Description = "Enable protection mode"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "EnableLUA"
            Value = 1
            Type = "DWORD"
            Description = "Enable User Account Control"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "ConsentPromptBehaviorAdmin"
            Value = 2
            Type = "DWORD"
            Description = "UAC prompt for administrators"
        }
    )
    
    foreach ($setting in $registrySettings) {
        try {
            if (!$DryRun) {
                if (!(Test-Path $setting.Path)) {
                    New-Item -Path $setting.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type
            }
            Write-Log "Applied registry setting: $($setting.Description)"
        }
        catch {
            Write-Log "Failed to apply registry setting $($setting.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Remove unnecessary Windows features
function Remove-UnnecessaryFeatures {
    Write-Log "Removing unnecessary Windows features"
    
    $featuresToRemove = @(
        "TelnetClient",
        "TelnetServer", 
        "SimpleUDP",
        "SNMP",
        "WCF-Services45",
        "MediaPlayback",
        "WindowsMediaPlayer",
        "Internet-Explorer-Optional-amd64"
    )
    
    foreach ($feature in $featuresToRemove) {
        try {
            $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureState -and $featureState.State -eq "Enabled") {
                if (!$DryRun) {
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
                }
                Write-Log "Disabled Windows feature: $feature"
            }
        }
        catch {
            Write-Log "Failed to disable feature $feature`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
}

# Configure Windows Update for ICS environment
function Configure-WindowsUpdate {
    Write-Log "Configuring Windows Update for ICS environment"
    
    try {
        if (!$DryRun) {
            # Disable automatic updates (manual control recommended for ICS)
            $updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            if (!(Test-Path $updatePath)) {
                New-Item -Path $updatePath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $updatePath -Name "NoAutoUpdate" -Value 1 -Type DWORD
            Set-ItemProperty -Path $updatePath -Name "AUOptions" -Value 2 -Type DWORD  # Notify only
        }
        Write-Log "Windows Update configured for manual control"
    }
    catch {
        Write-Log "Failed to configure Windows Update: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Create system backup before hardening
function Create-SystemBackup {
    param([string]$BackupLocation = "C:\ICS_Backup")
    
    Write-Log "Creating system backup before hardening"
    
    try {
        if (!$DryRun) {
            if (!(Test-Path $BackupLocation)) {
                New-Item -ItemType Directory -Path $BackupLocation -Force | Out-Null
            }
            
            # Export current firewall configuration
            netsh advfirewall export "$BackupLocation\firewall-backup-$(Get-Date -Format 'yyyyMMdd').wfw"
            
            # Export registry security settings
            secedit /export /cfg "$BackupLocation\security-backup-$(Get-Date -Format 'yyyyMMdd').inf"
            
            # Export current services configuration
            Get-Service | Export-Csv "$BackupLocation\services-backup-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
        }
        Write-Log "System backup created at: $BackupLocation"
    }
    catch {
        Write-Log "Failed to create system backup: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Generate hardening report
function Generate-HardeningReport {
    Write-Log "Generating hardening compliance report"
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        HardeningActions = @()
        SecurityChecks = @{}
    }
    
    # Check firewall status
    $firewallProfiles = Get-NetFirewallProfile
    $report.SecurityChecks.FirewallEnabled = ($firewallProfiles | Where-Object {$_.Enabled -eq $true}).Count -eq 3
    
    # Check UAC status
    $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    $report.SecurityChecks.UACEnabled = $uacStatus.EnableLUA -eq 1
    
    # Check disabled services
    $disabledServices = @("Spooler", "Fax", "WSearch") | ForEach-Object {
        $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($service -and $service.StartType -eq "Disabled") { $_ }
    }
    $report.SecurityChecks.UnnecessaryServicesDisabled = $disabledServices.Count -gt 0
    
    # Export report
    $reportPath = ".\logs\hardening-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    if (!(Test-Path (Split-Path $reportPath))) {
        New-Item -ItemType Directory -Path (Split-Path $reportPath) -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-Log "Hardening report generated: $reportPath"
}

# Main execution
function Main {
    Write-Log "Starting Windows ICS System Hardening Script"
    Write-Log "Version: 1.0.0"
    Write-Log "DryRun Mode: $DryRun"
    
    if (!(Test-AdminPrivileges)) {
        Write-Log "ERROR: This script requires administrator privileges" -Level "ERROR"
        exit 1
    }
    
    try {
        if (!$DryRun -and !$Force) {
            $confirmation = Read-Host "This will modify system settings. Continue? (y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Log "Hardening cancelled by user"
                exit 0
            }
        }
        
        # Create backup before making changes
        Create-SystemBackup
        
        # Apply hardening measures
        Disable-UnnecessaryServices
        Configure-WindowsFirewall
        Set-AccountPolicies
        Set-AuditPolicies
        Set-RegistrySettings
        Remove-UnnecessaryFeatures
        Configure-WindowsUpdate
        
        # Generate compliance report
        Generate-HardeningReport
        
        Write-Log "Windows ICS system hardening completed successfully"
        Write-Log "Please review the log file: $LogFile"
        Write-Log "A system restart may be required for all changes to take effect"
        
    }
    catch {
        Write-Log "Critical error during hardening process: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Execute main function
Main
