function Invoke-WPFPresets {
    <#

    .SYNOPSIS
        Sets the options in the tweaks panel to the given preset

    .PARAMETER preset
        The preset to set the options to

    .PARAMETER imported
        If the preset is imported from a file, defaults to false

    .PARAMETER checkboxfilterpattern
        The Pattern to use when filtering through CheckBoxes, defaults to "**"

    #>

    param (
        [Parameter(position=0)]
        [Array]$preset = "",

        [Parameter(position=1)]
        [bool]$imported = $false,

        [Parameter(position=2)]
        [string]$checkboxfilterpattern = "**"
    )

    if ($imported -eq $true) {
        $CheckBoxesToCheck = $preset
    } else {
        $CheckBoxesToCheck = $sync.configs.preset.$preset
    }

    $CheckBoxes = ($sync.GetEnumerator()).where{ $_.Value -is [System.Windows.Controls.CheckBox] -and $_.Name -notlike "WPFToggle*" -and $_.Name -like "$checkboxfilterpattern"}
    Write-Debug "Getting checkboxes to set, number of checkboxes: $($CheckBoxes.Count)"

    if ($CheckBoxesToCheck -ne "") {
        $debugMsg = "CheckBoxes to Check are: "
        $CheckBoxesToCheck | ForEach-Object { $debugMsg += "$_, " }
        $debugMsg = $debugMsg -replace (',\s*$', '')
        Write-Debug "$debugMsg"
    }

    foreach ($CheckBox in $CheckBoxes) {
        $checkboxName = $CheckBox.Key
        $checkbox = $CheckBox.Value

        if (-not $CheckBoxesToCheck) {
            $sync.$checkboxName.IsChecked = $false
            # If it's a WPFInstall checkbox, also remove from selectedApps
            if ($checkboxName -like "WPFInstall*") {
                # Use checkbox.Parent.Tag which contains the full app key (e.g., "WPFInstallchrome")
                # This matches what's stored in applicationsHashtable
                $appKey = if ($checkbox.Parent -and $checkbox.Parent.Tag) {
                    $checkbox.Parent.Tag
                } else {
                    # Fallback: use checkboxName directly (already has WPFInstall prefix)
                    $checkboxName
                }
                if ($appKey -and $sync.selectedApps -contains $appKey) {
                    $sync.selectedApps.Remove($appKey)
                }
            }
            continue
        }

        # Check if the checkbox name exists in the flattened JSON hashtable
        if ($CheckBoxesToCheck -contains $checkboxName) {
            # If it exists, set IsChecked to true
            $sync.$checkboxName.IsChecked = $true
            Write-Debug "$checkboxName is checked"
            # If it's a WPFInstall checkbox, also add to selectedApps
            if ($checkboxName -like "WPFInstall*") {
                # Use checkbox.Parent.Tag which contains the full app key (e.g., "WPFInstallchrome")
                # This matches what's stored in applicationsHashtable
                $appKey = if ($checkbox.Parent -and $checkbox.Parent.Tag) {
                    $checkbox.Parent.Tag
                } else {
                    # Fallback: use checkboxName directly (already has WPFInstall prefix)
                    $checkboxName
                }
                if ($appKey -and -not ($sync.selectedApps -contains $appKey)) {
                    $sync.selectedApps.Add($appKey)
                    [System.Collections.Generic.List[pscustomobject]]$sync.selectedApps = $sync.selectedApps | Sort-Object
                }
            }
        } else {
            # If it doesn't exist, set IsChecked to false
            $sync.$checkboxName.IsChecked = $false
            Write-Debug "$checkboxName is not checked"
            # If it's a WPFInstall checkbox, also remove from selectedApps
            if ($checkboxName -like "WPFInstall*") {
                # Use checkbox.Parent.Tag which contains the full app key (e.g., "WPFInstallchrome")
                # This matches what's stored in applicationsHashtable
                $appKey = if ($checkbox.Parent -and $checkbox.Parent.Tag) {
                    $checkbox.Parent.Tag
                } else {
                    # Fallback: use checkboxName directly (already has WPFInstall prefix)
                    $checkboxName
                }
                if ($appKey -and $sync.selectedApps -contains $appKey) {
                    $sync.selectedApps.Remove($appKey)
                }
            }
        }
    }

    # Update the selected apps button count if any WPFInstall checkboxes were modified
    if ($CheckBoxes | Where-Object { $_.Key -like "WPFInstall*" }) {
        $count = $sync.selectedApps.Count
        if ($sync.WPFselectedAppsButton) {
            $sync.WPFselectedAppsButton.Content = "Selected Apps: $count"
        }
        # Update the selected apps popup menu
        if ($sync.selectedAppsstackPanel) {
            $sync.selectedAppsstackPanel.Children.Clear()
            $sync.selectedApps | Foreach-Object {
                if ($sync.configs.applicationsHashtable.$_) {
                    Add-SelectedAppsMenuItem -name $($sync.configs.applicationsHashtable.$_.Content) -key $_
                }
            }
        }
    }
}
