#Requires -Version 5.1
param(
    [string]$Version = "",
    [switch]$NoBackup,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$Repo = "rhamdeew/go_gal"
$ServiceName = "go_gal"

function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-LogWarn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Show-Usage {
    Write-Host @"
Usage: .\update.ps1 [OPTIONS]

Options:
    -Version VERSION   Update to specific version (default: latest)
    -NoBackup          Skip backup creation (not recommended)
    -DryRun            Check for updates without installing
    -Help              Show this help message

Examples:
    .\update.ps1
    .\update.ps1 -Version v0.0.26
    .\update.ps1 -DryRun
"@
}

function Get-Platform {
    $os = "windows"
    $arch = $env:PROCESSOR_ARCHITECTURE.ToLower()
    
    if ($arch -eq "amd64" -or $arch -eq "x86_64") {
        $arch = "amd64"
    } elseif ($arch -eq "arm64") {
        $arch = "arm64"
    } else {
        Write-LogError "Unsupported architecture: $arch"
        exit 1
    }
    
    return "${os}_${arch}"
}

function Get-CurrentVersion {
    if (Test-Path ".\go_gal.exe") {
        try {
            $output = & .\go_gal.exe --version 2>&1
            if ($output -match "v\d+\.\d+\.\d+") {
                return $matches[0]
            }
            return "unknown"
        } catch {
            return "unknown"
        }
    }
    return "not installed"
}

function Get-LatestRelease {
    $apiUrl = "https://api.github.com/repos/${Repo}/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        return $response.tag_name
    } catch {
        Write-LogError "Failed to get latest release: $_"
        return $null
    }
}

function Get-InstalledKeys {
    param([string]$InstallDir)
    
    $envFile = Join-Path $InstallDir ".env"
    if (Test-Path $envFile) {
        $content = Get-Content $envFile
        foreach ($line in $content) {
            if ($line -match "GO_GAL_SESSION_KEY=(.+)") {
                $script:SessionKey = $matches[1].Trim('"')
            }
            if ($line -match "GO_GAL_SALT=(.+)") {
                $script:Salt = $matches[1].Trim('"')
            }
        }
    }
    
    if (-not $script:SessionKey) {
        $script:SessionKey = $env:GO_GAL_SESSION_KEY
    }
    if (-not $script:Salt) {
        $script:Salt = $env:GO_GAL_SALT
    }
}

function New-Backup {
    param([string]$InstallDir)
    
    $backupDir = "${InstallDir}_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-LogInfo "Creating backup at $backupDir..."
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Copy-Item -Path "$InstallDir\*" -Destination $backupDir -Recurse -Force
    
    Write-LogInfo "Backup created successfully"
    return $backupDir
}

function Restore-Backup {
    param([string]$InstallDir, [string]$BackupDir)
    
    Write-LogError "Update failed, restoring from backup..."
    
    Remove-Item -Path "$InstallDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$BackupDir\*" -Destination $InstallDir -Recurse -Force
    
    Write-LogInfo "Restored from backup"
}

function Stop-GoGalService {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-LogInfo "Stopping service..."
        Stop-Service -Name $ServiceName -Force
    } else {
        $process = Get-Process -Name "go_gal" -ErrorAction SilentlyContinue
        if ($process) {
            Write-LogInfo "Stopping go_gal process..."
            $process | Stop-Process -Force
        }
    }
}

function Start-GoGalService {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-LogInfo "Starting service..."
        Start-Service -Name $ServiceName
        Get-Service -Name $ServiceName
    } else {
        Write-LogInfo "Service not installed. Start go_gal.exe manually."
    }
}

function Invoke-Download {
    param([string]$Version, [string]$Platform)
    
    $downloadUrl = "https://github.com/${Repo}/releases/download/${Version}/go_gal_${Platform}.zip"
    $tempDir = New-TemporaryDirectory
    $archive = Join-Path $tempDir "go_gal.zip"
    
    Write-LogInfo "Downloading $Version for $Platform..."
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archive -UseBasicParsing
    } catch {
        Write-LogError "Failed to download release: $_"
        Remove-Item -Path $tempDir -Recurse -Force
        exit 1
    }
    
    Write-LogInfo "Extracting archive..."
    Expand-Archive -Path $archive -DestinationPath $tempDir -Force
    
    return $tempDir
}

function New-TemporaryDirectory {
    $tempPath = [System.IO.Path]::GetTempPath()
    $tempDir = Join-Path $tempPath "go_gal_update_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    return $tempDir
}

function Update-Files {
    param([string]$InstallDir, [string]$TempDir)
    
    Write-LogInfo "Updating files..."
    
    $oldBinary = Join-Path $InstallDir "go_gal.exe.old"
    if (Test-Path "$InstallDir\go_gal.exe") {
        Move-Item -Path "$InstallDir\go_gal.exe" -Destination $oldBinary -Force
    }
    
    Copy-Item -Path "$TempDir\go_gal.exe" -Destination $InstallDir -Force
    
    if (Test-Path "$TempDir\templates") {
        Copy-Item -Path "$TempDir\templates" -Destination $InstallDir -Recurse -Force
    }
    if (Test-Path "$TempDir\static") {
        Copy-Item -Path "$TempDir\static" -Destination $InstallDir -Recurse -Force
    }
    
    Remove-Item -Path $TempDir -Recurse -Force
    Remove-Item -Path $oldBinary -Force -ErrorAction SilentlyContinue
}

function Save-EnvironmentFile {
    param([string]$InstallDir)
    
    if ($script:SessionKey -and $script:Salt) {
        $envFile = Join-Path $InstallDir ".env"
        $envContent = @"
GO_GAL_SESSION_KEY=$($script:SessionKey)
GO_GAL_SALT=$($script:Salt)
"@
        Set-Content -Path $envFile -Value $envContent -Force
        Write-LogInfo "Environment saved to .env file"
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

$installDir = $PSScriptRoot
if (-not $installDir) {
    $installDir = Get-Location
}

Write-Host ""
Write-Host "=== Go Gallery Updater ===" -ForegroundColor Cyan
Write-Host ""

$currentVersion = Get-CurrentVersion
Write-LogInfo "Current version: $currentVersion"

if (-not $Version) {
    $Version = Get-LatestRelease
    if (-not $Version) {
        Write-LogError "Failed to get latest release"
        exit 1
    }
}

Write-LogInfo "Target version: $Version"

if ($currentVersion -eq $Version) {
    Write-LogInfo "Already up to date!"
    exit 0
}

if ($DryRun) {
    Write-LogInfo "Dry run complete. Run without -DryRun to update."
    exit 0
}

Get-InstalledKeys -InstallDir $installDir

if (-not $script:SessionKey -or -not $script:Salt) {
    Write-LogError "Could not find encryption keys"
    Write-LogError "Make sure GO_GAL_SESSION_KEY and GO_GAL_SALT are set"
    Write-LogError "Either as environment variables or in .env file"
    exit 1
}

Write-LogWarn "Important: Keep your encryption keys safe!"
Write-LogInfo "Session key: $($script:SessionKey.Substring(0, [Math]::Min(4, $script:SessionKey.Length)))****"
Write-LogInfo "Salt: $($script:Salt.Substring(0, [Math]::Min(4, $script:Salt.Length)))****"

$platform = Get-Platform
Write-LogInfo "Platform: $platform"

$tempDir = Invoke-Download -Version $Version -Platform $platform

$backupDir = $null
if (-not $NoBackup) {
    $backupDir = New-Backup -InstallDir $installDir
} else {
    Write-LogWarn "Skipping backup (-NoBackup)"
}

try {
    Stop-GoGalService
    Update-Files -InstallDir $installDir -TempDir $tempDir
    Save-EnvironmentFile -InstallDir $installDir
    Start-GoGalService
    
    if ($backupDir) {
        Write-LogInfo "Cleaning up backup..."
        Remove-Item -Path $backupDir -Recurse -Force
    }
    
    Write-Host ""
    Write-LogInfo "Update complete! Version: $Version"
} catch {
    Write-LogError "Update failed: $_"
    if ($backupDir) {
        Restore-Backup -InstallDir $installDir -BackupDir $backupDir
    }
    exit 1
}