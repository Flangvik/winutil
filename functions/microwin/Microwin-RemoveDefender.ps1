function Microwin-RemoveDefender {
    <#
        .SYNOPSIS
            Removes Windows Defender Platform folder from a mounted Windows image.

        .DESCRIPTION
            This function removes the Windows Defender Platform folder from a Windows ISO image.
            No registry modifications are performed to avoid system initialization issues.

        .PARAMETER ScratchDir
            The path to the mounted Windows image (scratch directory).

        .EXAMPLE
            Microwin-RemoveDefender -ScratchDir "C:\Scratch"
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScratchDir
    )

    Write-Host "Removing Windows Defender folders..."

    try {
        # List of Defender folders to remove
        $defenderFolders = @(
            "$($ScratchDir)\ProgramData\Microsoft\Windows Defender\Platform",
            "$($ScratchDir)\Program Files\Windows Defender",
            "$($ScratchDir)\Program Files\Windows Defender Advanced Threat Protection",
            "$($ScratchDir)\Program Files (x86)\Windows Defender"
        )

        foreach ($folderPath in $defenderFolders) {
            if (Test-Path -Path $folderPath) {
                try {
                    Write-Host "Removing: $folderPath"
                    Microwin-RemoveFileOrDirectory -pathToDelete $folderPath -Directory
                } catch {
                    Write-Host "Warning: Could not remove $folderPath : $_" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Folder not found at: $folderPath"
            }
        }
        Write-Host "Windows Defender folder removal complete!"
    } catch {
        Write-Host "Error during Defender folder removal: $_" -ForegroundColor Red
        Write-Host "Continuing with image processing..." -ForegroundColor Yellow
    }
}
