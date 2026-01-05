function Microwin-NewFirstRun {
    param(
        [Parameter(Mandatory=$false)]
        [bool]$AddActivationShortcut = $false
    )

    # using here string to embed firstrun
    $firstRun = @'
    # Set the global error action preference to continue
    $ErrorActionPreference = "Continue"

    # Initialize logging
    $logFile = "$env:HOMEDRIVE\windows\LogFirstRun.txt"
    function Write-Log {
        param([string]$Message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $Message" | Out-File -FilePath $logFile -Append -NoClobber
        Write-Host "$timestamp - $Message"
    }

    # Check if script is being run manually (not via FirstLogonCommands)
    $isManualRun = $false
    if ($MyInvocation.Line -or $PSCommandPath) {
        $isManualRun = $true
        Write-Log "=== Script executed manually (not via FirstLogonCommands) ==="
    }

    Write-Log "=== FirstRun Script Started ==="
    Write-Log "Script path: $($MyInvocation.PSCommandPath)"
    Write-Log "Command line: $($MyInvocation.Line)"
    Write-Log "Manual execution: $isManualRun"
    Write-Log "USERPROFILE: $env:USERPROFILE"
    Write-Log "HOMEDRIVE: $env:HOMEDRIVE"
    Write-Log "USERNAME: $env:USERNAME"

    # Set PowerShell execution policy for the entire system
    Write-Log "=== Setting PowerShell Execution Policy ==="
    try {
        Write-Log "Current execution policy: $((Get-ExecutionPolicy -List | Out-String).Trim())"
        Write-Log "Setting execution policy to RemoteSigned for LocalMachine scope..."
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
        Write-Log "SUCCESS: Execution policy set to RemoteSigned for LocalMachine"

        # Also set for CurrentUser as a fallback
        Write-Log "Setting execution policy to RemoteSigned for CurrentUser scope..."
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        Write-Log "Execution policy set for CurrentUser scope"

        # Verify the setting
        $localMachinePolicy = Get-ExecutionPolicy -Scope LocalMachine
        Write-Log "Verified LocalMachine execution policy: $localMachinePolicy"
    } catch {
        Write-Log "ERROR: Failed to set execution policy: $_"
        Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
        Write-Log "ERROR: Exception message: $($_.Exception.Message)"
        Write-Log "Attempting alternative method using registry..."
        try {
            # Alternative method: Set via registry directly
            $regPath = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name ExecutionPolicy -Value "RemoteSigned" -Force -ErrorAction Stop
                Write-Log "SUCCESS: Execution policy set via registry"
            } else {
                Write-Log "WARNING: Registry path for execution policy not found"
            }
        } catch {
            Write-Log "ERROR: Failed to set execution policy via registry: $_"
        }
    }
    Write-Log "=== PowerShell Execution Policy Configuration Completed ==="

'@

    # Add activation shortcut code early if requested (before desktop cleanup)
    if ($AddActivationShortcut) {
        $activationShortcutCode = @'

    # Create activation shortcut on the local user's desktop (the user created by MicroWin)
    # This is done early to ensure it's created before any desktop cleanup operations
    Write-Log "=== Starting Activation Shortcut Creation ==="
    try {
        # Find the actual user folder by scanning C:\Users and excluding system folders
        Write-Log "Finding actual user folder..."
        $usersPath = "$env:HOMEDRIVE\Users"
        Write-Log "Scanning Users directory: $usersPath"

        # System folders to exclude
        $excludedFolders = @("Default", "Public", "All Users", "Default User")

        # Get all folders in Users directory
        $userFolders = Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue
        Write-Log "Found $($userFolders.Count) folders in Users directory"
        Write-Log "Folders found: $($userFolders.Name -join ', ')"

        # Find the first folder that's not in the excluded list
        $actualUserFolder = $null
        foreach ($folder in $userFolders) {
            if ($folder.Name -notin $excludedFolders) {
                $actualUserFolder = $folder.FullName
                Write-Log "Found user folder: $actualUserFolder"
                break
            }
        }

        if ($null -eq $actualUserFolder) {
            Write-Log "ERROR: Could not find actual user folder in $usersPath"
            Write-Log "Available folders: $($userFolders.Name -join ', ')"
            Write-Log "Excluded folders: $($excludedFolders -join ', ')"
            Write-Log "Cannot create activation shortcut - no user folder found"
            throw "No user folder found in Users directory"
        }

        # Use the found user folder - construct desktop path directly
        $userDesktop = Join-Path $actualUserFolder "Desktop"
        Write-Log "Using user folder desktop path: $userDesktop"

        Write-Log "Final desktop path: $userDesktop"
        Write-Log "Desktop path exists: $(Test-Path -Path $userDesktop)"

        if (Test-Path -Path $userDesktop) {
            $shortcutPath = Join-Path $userDesktop "Activate Windows.lnk"
            Write-Log "Target shortcut path: $shortcutPath"
            Write-Log "Shortcut already exists: $(Test-Path -Path $shortcutPath)"

            # Check what's currently on the desktop
            $desktopContents = Get-ChildItem -Path $userDesktop -ErrorAction SilentlyContinue
            Write-Log "Current desktop contents count: $($desktopContents.Count)"
            if ($desktopContents.Count -gt 0) {
                Write-Log "Desktop contents: $($desktopContents.Name -join ', ')"
            }

            Write-Log "Creating WScript.Shell COM object"
            $WshShell = New-Object -ComObject WScript.Shell
            Write-Log "Creating shortcut object"
            $Shortcut = $WshShell.CreateShortcut($shortcutPath)
            Write-Log "Setting shortcut properties"
            $Shortcut.TargetPath = "powershell.exe"
            Write-Log "TargetPath set to: $($Shortcut.TargetPath)"

            # Encode the activation command to avoid quote escaping issues
            $activationCmd = "irm https://get.activated.win | iex"
            Write-Log "Activation command: $activationCmd"
            Write-Log "Encoding activation command"
            $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($activationCmd))
            Write-Log "Activation command encoded (length: $($encodedCmd.Length))"
            Write-Log "Encoded command: $encodedCmd"

            # Build elevation command with proper variable expansion
            # Use double quotes for the encoded command part so $encodedCmd expands at runtime
            $elevationCmd = 'Start-Process powershell.exe -ArgumentList @(''-NoProfile'', ''-ExecutionPolicy'', ''Bypass'', ''-EncodedCommand'', "' + $encodedCmd + '") -Verb RunAs'
            Write-Log "Elevation command: $elevationCmd"
            Write-Log "Encoding elevation command"
            $elevationEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($elevationCmd))
            Write-Log "Elevation command encoded (length: $($elevationEncoded.Length))"
            Write-Log "Final encoded command: $elevationEncoded"

            $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $elevationEncoded"
            Write-Log "Shortcut arguments: $($Shortcut.Arguments)"
            Write-Log "Arguments set (length: $($Shortcut.Arguments.Length))"
            $Shortcut.Description = "Activate Windows"
            $Shortcut.WorkingDirectory = "$env:SystemRoot\System32"
            $Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,27"

            Write-Log "Saving shortcut to: $shortcutPath"
            $Shortcut.Save()
            Write-Log "Shortcut saved successfully"

            # Verify shortcut was created
            if (Test-Path -Path $shortcutPath) {
                $shortcutInfo = Get-Item -Path $shortcutPath
                Write-Log "Shortcut file verified - Size: $($shortcutInfo.Length) bytes, Created: $($shortcutInfo.CreationTime)"
            } else {
                Write-Log "ERROR: Shortcut file was not created at: $shortcutPath"
            }

            # Set the "Run as administrator" flag on the shortcut
            Write-Log "Setting 'Run as administrator' flag on shortcut"
            $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
            Write-Log "Read shortcut file bytes (length: $($bytes.Length))"
            if ($bytes.Length -gt 0x15) {
                $bytes[0x15] = $bytes[0x15] -bor 0x20
                [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
                Write-Log "Administrator flag set successfully"
            } else {
                Write-Log "WARNING: Shortcut file too small to set administrator flag (length: $($bytes.Length))"
            }

            # Final verification
            $finalCheck = Get-ChildItem -Path $userDesktop -Filter "*.lnk" -ErrorAction SilentlyContinue
            Write-Log "Final desktop .lnk files count: $($finalCheck.Count)"
            if ($finalCheck.Count -gt 0) {
                Write-Log "Final desktop .lnk files: $($finalCheck.Name -join ', ')"
            }

            if (Test-Path -Path $shortcutPath) {
                Write-Log "SUCCESS: Activation shortcut created successfully at: $shortcutPath"
                Write-Host "Activation shortcut created on user desktop"
            } else {
                Write-Log "ERROR: Activation shortcut was not found after creation attempt"
            }
        } else {
            Write-Log "ERROR: Desktop path does not exist: $userDesktop"
            Write-Log "Cannot create activation shortcut - desktop path unavailable"
        }
    } catch {
        Write-Log "ERROR: Exception occurred while creating activation shortcut: $_"
        Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
        Write-Log "ERROR: Exception message: $($_.Exception.Message)"
        Write-Log "ERROR: Stack trace: $($_.ScriptStackTrace)"
        Write-Host "Warning: Could not create activation shortcut: $_"
    }
    Write-Log "=== Activation Shortcut Creation Completed ==="

'@
        $firstRun += $activationShortcutCode
    }

    # Continue with the rest of the script
    $firstRun += @'

    # Backup Defender removal - runs early before Defender can activate
    try {
        "Defender removal backup started at $(Get-Date)" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append -NoClobber

        # List of Defender folders to remove
        $defenderFolders = @(
            "$env:ProgramData\Microsoft\Windows Defender\Platform",
            "$env:ProgramFiles\Windows Defender",
            "$env:ProgramFiles\Windows Defender Advanced Threat Protection"
        )

        foreach ($folderPath in $defenderFolders) {
            if (Test-Path -Path $folderPath) {
                try {
                    # Take ownership and remove
                    takeown /f "$folderPath" /r /d Y >$null 2>&1
                    icacls "$folderPath" /grant administrators:F /t >$null 2>&1
                    Remove-Item -Path "$folderPath" -Recurse -Force -ErrorAction SilentlyContinue
                    "Removed folder: $folderPath" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append
                } catch {
                    "Could not remove folder $folderPath : $_" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append
                }
            } else {
                "Folder not found at: $folderPath" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append
            }
        }

        "Defender removal backup completed at $(Get-Date)" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append
    } catch {
        "Error during Defender removal backup: $_" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append
    }

    function Remove-RegistryValue {
        param (
            [Parameter(Mandatory = $true)]
            [string]$RegistryPath,

            [Parameter(Mandatory = $true)]
            [string]$ValueName
        )

        # Check if the registry path exists
        if (Test-Path -Path $RegistryPath) {
            $registryValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

            # Check if the registry value exists
            if ($registryValue) {
                # Remove the registry value
                Remove-ItemProperty -Path $RegistryPath -Name $ValueName -Force
                Write-Host "Registry value '$ValueName' removed from '$RegistryPath'."
            } else {
                Write-Host "Registry value '$ValueName' not found in '$RegistryPath'."
            }
        } else {
            Write-Host "Registry path '$RegistryPath' not found."
        }
    }

    Write-Log "FirstStartup script execution started"

    $taskbarPath = "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    Write-Log "Cleaning taskbar pinned items from: $taskbarPath"
    # Delete all files on the Taskbar
    if (Test-Path "$taskbarPath") {
        $taskbarFiles = Get-ChildItem -Path $taskbarPath -File -ErrorAction SilentlyContinue
        Write-Log "Found $($taskbarFiles.Count) files on taskbar to remove"
        $taskbarFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Taskbar cleanup completed"
    } else {
        Write-Log "Taskbar path not found: $taskbarPath"
    }
    Write-Log "Cleaning taskbar registry values"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesRemovedChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "Favorites"
    Write-Log "Taskbar registry cleanup completed"

    # Log desktop contents (no cleanup - preserving all shortcuts)
    Write-Log "=== Desktop Contents Check ==="

    # Find the actual user folder by scanning C:\Users and excluding system folders
    Write-Log "Finding actual user folder for desktop cleanup..."
    $usersPath = "$env:HOMEDRIVE\Users"
    $excludedFolders = @("Default", "Public", "All Users", "Default User")
    $userFolders = Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue
    Write-Log "Found $($userFolders.Count) folders in Users directory: $($userFolders.Name -join ', ')"

    # Find the first folder that's not in the excluded list
    $actualUserFolder = $null
    foreach ($folder in $userFolders) {
        if ($folder.Name -notin $excludedFolders) {
            $actualUserFolder = $folder.FullName
            Write-Log "Found user folder for cleanup: $actualUserFolder"
            break
        }
    }

    if ($null -eq $actualUserFolder) {
        Write-Log "ERROR: Could not find actual user folder in $usersPath"
        Write-Log "Available folders: $($userFolders.Name -join ', ')"
        Write-Log "Excluded folders: $($excludedFolders -join ', ')"
        Write-Log "Cannot proceed with desktop cleanup - no user folder found"
        $desktopPath = $null
    } else {
        $desktopPath = Join-Path $actualUserFolder "Desktop"
    }

    if ($null -eq $desktopPath) {
        Write-Log "ERROR: Desktop cleanup skipped - no valid user folder found"
    } else {
        Write-Log "Desktop path for cleanup: $desktopPath"
        Write-Log "Desktop path exists: $(Test-Path -Path $desktopPath)"

        if (Test-Path -Path $desktopPath) {
            $allDesktopFiles = Get-ChildItem -Path $desktopPath -ErrorAction SilentlyContinue
            Write-Log "Total files/folders on desktop before cleanup: $($allDesktopFiles.Count)"
            $desktopLnkFiles = Get-ChildItem -Path $desktopPath -Filter "*.lnk" -ErrorAction SilentlyContinue
            Write-Log "Total .lnk files on desktop before cleanup: $($desktopLnkFiles.Count)"
            if ($desktopLnkFiles.Count -gt 0) {
                Write-Log "Desktop .lnk files found: $($desktopLnkFiles.Name -join ', ')"
            }
        } else {
            Write-Log "WARNING: Desktop path does not exist: $desktopPath"
        }

        # Log desktop contents but do not remove any .lnk files
        $edgeShortcutFiles = Get-ChildItem -Path $desktopPath -Filter "*Edge*.lnk" -ErrorAction SilentlyContinue
        Write-Log "Edge shortcut files found: $($edgeShortcutFiles.Count) (not removing)"

        $allLnkFiles = Get-ChildItem -Path "$desktopPath\*.lnk" -ErrorAction SilentlyContinue
        Write-Log "Total .lnk files on desktop: $($allLnkFiles.Count) (preserving all shortcuts)"
        if ($allLnkFiles.Count -gt 0) {
            Write-Log "Desktop .lnk files: $($allLnkFiles.Name -join ', ')"
        }
    }

    # Log default user desktop but do not remove any .lnk files
    # Find Default user folder dynamically by traversing Users directory
    Write-Log "Finding Default user folder..."
    $defaultUserFolder = $null
    foreach ($folder in $userFolders) {
        if ($folder.Name -eq "Default") {
            $defaultUserFolder = $folder.FullName
            Write-Log "Found Default user folder: $defaultUserFolder"
            break
        }
    }

    if ($null -ne $defaultUserFolder) {
        $defaultDesktopPath = Join-Path $defaultUserFolder "Desktop"
        if (Test-Path -Path $defaultDesktopPath) {
            $defaultLnkFiles = Get-ChildItem -Path "$defaultDesktopPath\*.lnk" -ErrorAction SilentlyContinue
            Write-Log "Default user desktop .lnk files: $($defaultLnkFiles.Count) (preserving all shortcuts)"
        } else {
            Write-Log "Default user desktop path does not exist: $defaultDesktopPath"
        }
    } else {
        Write-Log "Default user folder not found in Users directory"
    }

    Write-Log "=== Desktop Cleanup Completed ==="

    Write-Log "Checking for Recall feature"
    try
    {
        $recallFeature = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -like "Recall" }
        if ($recallFeature.Count -gt 0)
        {
            Write-Log "Recall feature found and enabled, disabling it"
            Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove
            Write-Log "Recall feature disabled"
        } else {
            Write-Log "Recall feature not found or not enabled"
        }
    }
    catch
    {
        Write-Log "Error checking/disabling Recall feature: $_"
    }

    # Get BCD entries and set bootmgr timeout accordingly
    Write-Log "Checking BCD entries for bootmgr timeout"
    try
    {
        # Check if the number of occurrences of "path" is 2 - this fixes the Boot Manager screen issue (#2562)
        $bcdPathCount = (bcdedit | Select-String "path").Count
        Write-Log "BCD path entries found: $bcdPathCount"
        if ($bcdPathCount -eq 2)
        {
            Write-Log "Setting bootmgr timeout to 0"
            # Set bootmgr timeout to 0
            bcdedit /set `{bootmgr`} timeout 0
            Write-Log "Bootmgr timeout set successfully"
        } else {
            Write-Log "Bootmgr timeout not changed (path count: $bcdPathCount, expected: 2)"
        }
    }
    catch
    {
        Write-Log "Error setting bootmgr timeout: $_"
    }

    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AccountHealth" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AccountHealth" /v Enabled /t REG_DWORD /d 0 /f

    # This will set List view in Start menu on Win11 25H2. This will not do anything in 24H2 and older
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v AllAppsViewMode /t REG_DWORD /d 2 /f

    # This will disable the Recommendations in 25H2. This is much simpler than the method used in 24H2 that requires the Education Environment policy
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f

    # Other Start Menu settings
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_AccountNotifications /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v ShowAllPinsList /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v ShowFrequentList /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v ShowRecentList /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f

    # Set taskbar alignment to left (0 = left, 1 = center)
    Write-Log "Setting taskbar alignment to left"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f
    Write-Log "Taskbar alignment set to left"

    Write-Log "=== FirstRun Script Main Section Completed ==="

    # Install VMware Tools via Chocolatey
    Write-Log "=== Starting VMware Tools Installation ==="
    try {
        # Check if Chocolatey is installed
        Write-Log "Checking if Chocolatey is installed..."
        $chocoInstalled = $false
        if (Get-Command -Name choco -ErrorAction SilentlyContinue) {
            $chocoInstalled = $true
            Write-Log "Chocolatey is already installed"
        } elseif (Test-Path -Path "$env:ProgramData\chocolatey\choco.exe") {
            $chocoInstalled = $true
            Write-Log "Chocolatey found at $env:ProgramData\chocolatey\choco.exe"
            # Refresh environment variables to make choco available in PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        } else {
            Write-Log "Chocolatey is not installed, attempting to install..."
        }

        # Install Chocolatey if not installed
        if (-not $chocoInstalled) {
            try {
                Write-Log "Installing Chocolatey..."
                Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                $chocoInstallScript = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
                Invoke-Expression $chocoInstallScript
                Write-Log "Chocolatey installation script executed"

                # Refresh environment variables after installation
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                Start-Sleep -Seconds 2

                # Verify installation
                if (Get-Command -Name choco -ErrorAction SilentlyContinue) {
                    Write-Log "Chocolatey installed successfully"
                    $chocoInstalled = $true
                } else {
                    Write-Log "WARNING: Chocolatey installation may have failed - choco command not found"
                }
            } catch {
                Write-Log "ERROR: Failed to install Chocolatey: $_"
                Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
                Write-Log "ERROR: Exception message: $($_.Exception.Message)"
            }
        }

        # Install VMware Tools if Chocolatey is available
        if ($chocoInstalled) {
            try {
                Write-Log "Installing VMware Tools via Chocolatey..."
                Write-Log "Running command: choco install vmware-tools -y"

                # Use Start-Process to capture output and handle errors gracefully
                $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processInfo.FileName = "choco"
                $processInfo.Arguments = "install vmware-tools -y"
                $processInfo.UseShellExecute = $false
                $processInfo.RedirectStandardOutput = $true
                $processInfo.RedirectStandardError = $true
                $processInfo.CreateNoWindow = $true

                $process = New-Object System.Diagnostics.Process
                $process.StartInfo = $processInfo
                $process.Start() | Out-Null

                $output = $process.StandardOutput.ReadToEnd()
                $errorOutput = $process.StandardError.ReadToEnd()
                $process.WaitForExit()
                $exitCode = $process.ExitCode

                Write-Log "Chocolatey command exit code: $exitCode"
                if ($output) {
                    Write-Log "Chocolatey output: $output"
                }
                if ($errorOutput) {
                    Write-Log "Chocolatey error output: $errorOutput"
                }

                if ($exitCode -eq 0) {
                    Write-Log "SUCCESS: VMware Tools installed successfully"
                } else {
                    Write-Log "WARNING: VMware Tools installation returned exit code $exitCode (may already be installed or installation failed)"
                }
            } catch {
                Write-Log "ERROR: Exception occurred while installing VMware Tools: $_"
                Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
                Write-Log "ERROR: Exception message: $($_.Exception.Message)"
                Write-Log "ERROR: Stack trace: $($_.ScriptStackTrace)"
            }
        } else {
            Write-Log "WARNING: Skipping VMware Tools installation - Chocolatey is not available"
        }
    } catch {
        Write-Log "ERROR: Unexpected error in VMware Tools installation section: $_"
        Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
        Write-Log "ERROR: Exception message: $($_.Exception.Message)"
    }
    Write-Log "=== VMware Tools Installation Completed ==="

    Clear-Host
    Write-Host "The taskbar will take around a minute to show up, but you can start using your computer now. Try pressing the Windows key to open the Start menu, or Windows + E to launch File Explorer."
    Write-Log "Waiting 10 seconds before checking for config file"
    Start-Sleep -Seconds 10

    if (Test-Path -Path "$env:HOMEDRIVE\winutil-config.json")
    {
        Write-Log "Configuration file detected at: $env:HOMEDRIVE\winutil-config.json"
        Write-Host "Configuration file detected. Applying..."
        Write-Log "Executing winutil config file"
        iex "& { $(irm https://raw.githubusercontent.com/Flangvik/winutil/refs/heads/main/winutil.ps1) } -Config `"$env:HOMEDRIVE\winutil-config.json`" -Run"
        Write-Log "Winutil config execution completed"
    } else {
        Write-Log "No configuration file found at: $env:HOMEDRIVE\winutil-config.json"
    }

    Write-Log "=== FirstRun Script Execution Completed ==="

'@

    $firstRun | Out-File -FilePath "$env:temp\FirstStartup.ps1" -Force
}
