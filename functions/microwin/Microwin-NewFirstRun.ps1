function Microwin-NewFirstRun {
    param(
        [Parameter(Mandatory=$false)]
        [bool]$AddActivationShortcut = $false
    )

    # using here string to embed firstrun
    $firstRun = @'
    # Set the global error action preference to continue
    $ErrorActionPreference = "Continue"

    # Backup Defender removal - runs early before Defender can activate
    try {
        "Defender removal backup started at $(Get-Date)" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogDefenderRemoval.txt" -Append -NoClobber

        # List of Defender folders to remove
        $defenderFolders = @(
            "$env:ProgramData\Microsoft\Windows Defender\Platform",
            "$env:ProgramFiles\Windows Defender",
            "$env:ProgramFiles\Windows Defender Advanced Threat Protection",
            "${env:ProgramFiles(x86)}\Windows Defender"
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

    "FirstStartup has worked" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

    $taskbarPath = "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    # Delete all files on the Taskbar
    if (Test-Path "$taskbarPath") {
        Get-ChildItem -Path $taskbarPath -File | Remove-Item -Force
    }
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesRemovedChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "Favorites"

    # Delete Edge Icon from the desktop
    $edgeShortcutFiles = Get-ChildItem -Path $desktopPath -Filter "*Edge*.lnk"
    # Check if Edge shortcuts exist on the desktop
    if ($edgeShortcutFiles) {
        foreach ($shortcutFile in $edgeShortcutFiles) {
            # Remove each Edge shortcut
            Remove-Item -Path $shortcutFile.FullName -Force
            Write-Host "Edge shortcut '$($shortcutFile.Name)' removed from the desktop."
        }
    }
    Remove-Item -Path "$env:USERPROFILE\Desktop\*.lnk"
    Remove-Item -Path "$env:HOMEDRIVE\Users\Default\Desktop\*.lnk"

    try
    {
        if ((Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -like "Recall" }).Count -gt 0)
        {
            Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove
        }
    }
    catch
    {

    }

    # Get BCD entries and set bootmgr timeout accordingly
    try
    {
        # Check if the number of occurrences of "path" is 2 - this fixes the Boot Manager screen issue (#2562)
        if ((bcdedit | Select-String "path").Count -eq 2)
        {
            # Set bootmgr timeout to 0
            bcdedit /set `{bootmgr`} timeout 0
        }
    }
    catch
    {

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
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f

    Clear-Host
    Write-Host "The taskbar will take around a minute to show up, but you can start using your computer now. Try pressing the Windows key to open the Start menu, or Windows + E to launch File Explorer."
    Start-Sleep -Seconds 10

    if (Test-Path -Path "$env:HOMEDRIVE\winutil-config.json")
    {
        Write-Host "Configuration file detected. Applying..."
        iex "& { $(irm https://raw.githubusercontent.com/Flangvik/winutil/refs/heads/main/winutil.ps1) } -Config `"$env:HOMEDRIVE\winutil-config.json`" -Run"
    }

'@

    # Add activation shortcut code if requested
    if ($AddActivationShortcut) {
        $activationShortcutCode = @'

    # Create activation shortcut on the local user's desktop (the user created by MicroWin)
    try {
        # Use the current logged-in user's desktop (MicroWin creates the user and auto-logs them in)
        $userDesktop = [Environment]::GetFolderPath('Desktop')
        if (-not (Test-Path -Path $userDesktop)) {
            # Fallback to USERPROFILE\Desktop if GetFolderPath doesn't work
            $userDesktop = Join-Path $env:USERPROFILE "Desktop"
        }

        if (Test-Path -Path $userDesktop) {
            $shortcutPath = Join-Path $userDesktop "Activate Windows.lnk"
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($shortcutPath)
            $Shortcut.TargetPath = "powershell.exe"
            # Encode the activation command to avoid quote escaping issues
            $activationCmd = "irm https://get.activated.win | iex"
            $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($activationCmd))
            # Use encoded command in Start-Process to avoid nested quote issues
            $elevationCmd = "Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', '$encodedCmd') -Verb RunAs"
            $elevationEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($elevationCmd))
            $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $elevationEncoded"
            $Shortcut.Description = "Activate Windows"
            $Shortcut.WorkingDirectory = "$env:SystemRoot\System32"
            $Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,27"
            $Shortcut.Save()

            # Set the "Run as administrator" flag on the shortcut
            $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
            if ($bytes.Length -gt 0x15) {
                $bytes[0x15] = $bytes[0x15] -bor 0x20
                [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
            }

            Write-Host "Activation shortcut created on user desktop"
        }
    } catch {
        Write-Host "Warning: Could not create activation shortcut: $_"
    }

'@
        $firstRun += $activationShortcutCode
    }

    $firstRun | Out-File -FilePath "$env:temp\FirstStartup.ps1" -Force
}
