function Invoke-WPFInstall {
    param (
        [Parameter(Mandatory=$false)]
        [PSObject[]]$PackagesToInstall = $($sync.selectedApps | Foreach-Object { $sync.configs.applicationsHashtable.$_ })
    )
    <#
    .SYNOPSIS
        Installs the selected programs using winget, if one or more of the selected programs are already installed on the system, winget will try and perform an upgrade if there's a newer version to install.
    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFInstall] An Install process is currently running."
        Write-Host $msg -ForegroundColor Yellow
        # Only show message box if form is visible (not in headless run mode)
        try {
            if ($sync.Form -and $sync.Form.IsVisible) {
                [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        } catch {
            # Form might not be initialized, continue without message box
        }
        return
    }

    if ($PackagesToInstall.Count -eq 0) {
        $WarningMsg = "Please select the program(s) to install or upgrade"
        Write-Host $WarningMsg -ForegroundColor Yellow
        Write-Host "Selected apps count: $($sync.selectedApps.Count)" -ForegroundColor Yellow
        if ($sync.selectedApps.Count -gt 0) {
            Write-Host "Selected apps list: $($sync.selectedApps -join ', ')" -ForegroundColor Yellow
            Write-Host "Applications hashtable keys count: $($sync.configs.applicationsHashtable.Keys.Count)" -ForegroundColor Yellow
            # Try to debug why packages aren't being built
            foreach ($appKey in $sync.selectedApps) {
                if ($sync.configs.applicationsHashtable.$appKey) {
                    Write-Host "  Found: $appKey -> $($sync.configs.applicationsHashtable.$appKey.Content)" -ForegroundColor Green
                } else {
                    Write-Host "  Missing: $appKey (not in applicationsHashtable)" -ForegroundColor Red
                }
            }
        }
        # Only show message box if form is visible (not in headless run mode)
        try {
            if ($sync.Form -and $sync.Form.IsVisible) {
                [System.Windows.MessageBox]::Show($WarningMsg, $AppTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        } catch {
            # Form might not be initialized, continue without message box
        }
        return
    }

    Write-Host "Invoke-WPFInstall called with $($PackagesToInstall.Count) packages to install" -ForegroundColor Green
    Write-Host "Package names: $($PackagesToInstall.Content -join ', ')" -ForegroundColor Cyan

    $ManagerPreference = $sync["ManagerPreference"]

    Invoke-WPFRunspace -ParameterList @(("PackagesToInstall", $PackagesToInstall),("ManagerPreference", $ManagerPreference)) -DebugPreference $DebugPreference -ScriptBlock {
        param($PackagesToInstall, $ManagerPreference, $DebugPreference)

        $packagesSorted = Get-WinUtilSelectedPackages -PackageList $PackagesToInstall -Preference $ManagerPreference

        $packagesWinget = $packagesSorted[[PackageManagers]::Winget]
        $packagesChoco = $packagesSorted[[PackageManagers]::Choco]

        try {
            $sync.ProcessRunning = $true
            if($packagesWinget.Count -gt 0 -and $packagesWinget -ne "0") {
                Show-WPFInstallAppBusy -text "Installing apps..."
                Install-WinUtilWinget
                Install-WinUtilProgramWinget -Action Install -Programs $packagesWinget
            }
            if($packagesChoco.Count -gt 0) {
                Install-WinUtilChoco
                Install-WinUtilProgramChoco -Action Install -Programs $packagesChoco
            }
            Hide-WPFInstallAppBusy
            Write-Host "==========================================="
            Write-Host "--      Installs have finished          ---"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
        } catch {
            Write-Host "==========================================="
            Write-Host "Error: $_"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" -overlay "warning" })
        }
        $sync.ProcessRunning = $False
    }
}
