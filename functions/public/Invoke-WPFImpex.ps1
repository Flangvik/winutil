function Invoke-WPFImpex {
    <#

    .SYNOPSIS
        Handles importing and exporting of the checkboxes checked for the tweaks section

    .PARAMETER type
        Indicates whether to 'import' or 'export'

    .PARAMETER checkbox
        The checkbox to export to a file or apply the imported file to

    .EXAMPLE
        Invoke-WPFImpex -type "export"

    #>
    param(
        $type,
        $Config = $null
    )

    function ConfigDialog {
        if (!$Config) {
            switch ($type) {
                "export" { $FileBrowser = New-Object System.Windows.Forms.SaveFileDialog }
                "import" { $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog }
            }
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $FileBrowser.Filter = "JSON Files (*.json)|*.json"
            $FileBrowser.ShowDialog() | Out-Null

            if ($FileBrowser.FileName -eq "") {
                return $null
            } else {
                return $FileBrowser.FileName
            }
        } else {
            return $Config
        }
    }

    switch ($type) {
        "export" {
            try {
                $Config = ConfigDialog
                if ($Config) {
                    $jsonFile = Get-WinUtilCheckBoxes -unCheck $false
                    # Add ManagerPreference to the export
                    $jsonFile["ManagerPreference"] = $sync["ManagerPreference"]
                    $jsonFile | ConvertTo-Json | Out-File $Config -Force
                    "iex ""& { `$(irm https://christitus.com/win) } -Config '$Config'""" | Set-Clipboard
                }
            } catch {
                Write-Error "An error occurred while exporting: $_"
            }
        }
        "import" {
            try {
                $Config = ConfigDialog
                if ($Config) {
                    try {
                        if ($Config -match '^https?://') {
                            $jsonFile = (Invoke-WebRequest "$Config").Content | ConvertFrom-Json
                        } else {
                            $jsonFile = Get-Content $Config | ConvertFrom-Json
                        }
                    } catch {
                        Write-Error "Failed to load the JSON file from the specified path or URL: $_"
                        return
                    }
                    # Import ManagerPreference if present
                    if ($jsonFile.PSObject.Properties.Name -contains "ManagerPreference") {
                        $preference = $jsonFile.ManagerPreference
                        if ($preference -eq "Winget" -or $preference -eq "Choco") {
                            Set-PackageManagerPreference -preferredPackageManager $preference
                            # Update UI radio buttons to reflect the imported preference
                            if ($sync.ChocoRadioButton -and $sync.WingetRadioButton) {
                                switch ($preference) {
                                    "Choco" {
                                        $sync.ChocoRadioButton.IsChecked = $true
                                        $sync.WingetRadioButton.IsChecked = $false
                                    }
                                    "Winget" {
                                        $sync.WingetRadioButton.IsChecked = $true
                                        $sync.ChocoRadioButton.IsChecked = $false
                                    }
                                }
                            }
                            Write-Host "Package Manager Preference set to: $preference"
                        }
                    }

                    # Directly populate selectedApps from WPFInstall array in config
                    # This ensures apps are available for installation even if checkboxes aren't found yet
                    if ($jsonFile.PSObject.Properties.Name -contains "WPFInstall" -and $jsonFile.WPFInstall) {
                        if (-not $sync.selectedApps) {
                            $sync.selectedApps = [System.Collections.Generic.List[pscustomobject]]::new()
                        }
                        # Clear existing selections and add from config
                        $sync.selectedApps.Clear()
                        foreach ($appKey in $jsonFile.WPFInstall) {
                            if ($appKey -and -not ($sync.selectedApps -contains $appKey)) {
                                $sync.selectedApps.Add($appKey)
                            }
                        }
                        [System.Collections.Generic.List[pscustomobject]]$sync.selectedApps = $sync.selectedApps | Sort-Object
                        Write-Debug "Populated selectedApps from config: $($sync.selectedApps.Count) apps"
                    }

                    $flattenedJson = $jsonFile.PSObject.Properties.Where({ $_.Name -ne "Install" -and $_.Name -ne "ManagerPreference" }).ForEach({ $_.Value })
                    Invoke-WPFPresets -preset $flattenedJson -imported $true
                }
            } catch {
                Write-Error "An error occurred while importing: $_"
            }
        }
    }
}
