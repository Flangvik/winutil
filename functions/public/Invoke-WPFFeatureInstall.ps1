function Invoke-WPFFeatureInstall {
    <#

    .SYNOPSIS
        Installs selected Windows Features

    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFFeatureInstall] Install process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $Features = (Get-WinUtilCheckBoxes)["WPFFeature"]

    Invoke-WPFRunspace -ArgumentList $Features -DebugPreference $DebugPreference -ScriptBlock {
        param($Features, $DebugPreference)
        $sync.ProcessRunning = $true
        try {
            if ($Features.count -eq 1) {
                $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
            } else {
                $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
            }

            Invoke-WinUtilFeatureInstall $Features

            Write-Host "==================================="
            Write-Host "---   Features are Installed    ---"
            Write-Host "---  A Reboot may be required   ---"
            Write-Host "==================================="
        } catch {
            Write-Host "==================================="
            Write-Host "ERROR: Feature installation failed: $_" -ForegroundColor Red
            Write-Host "==================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" -overlay "warning" })
        } finally {
            # Always reset ProcessRunning, even if there was an error
            $sync.ProcessRunning = $false
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
            Write-Host "Feature installation process completed. ProcessRunning reset to false." -ForegroundColor Green
        }
    }
}
