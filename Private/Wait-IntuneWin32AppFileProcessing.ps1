function Wait-IntuneWin32AppFileProcessing {
    <#
    .SYNOPSIS
        Wait for contentVersions/files resource processing.

    .DESCRIPTION
        Wait for contentVersions/files resource processing.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Stage,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    
    # Initialize poll counter for progressive backoff
    $PollCount = 0
    
    do {
        $GraphRequest = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $Resource
        switch ($GraphRequest.uploadState) {
            "$($Stage)Pending" {
                $PollCount++
                
                # Progressive backoff: 1s for first 5 polls, 3s for next 10 polls, 5s thereafter
                if ($PollCount -le 5) {
                    $WaitSeconds = 1
                }
                elseif ($PollCount -le 15) {
                    $WaitSeconds = 3
                }
                else {
                    $WaitSeconds = 5
                }
                
                Write-Verbose -Message "Intune service request for operation '$($Stage)' is in pending state (attempt $($PollCount)), waiting $($WaitSeconds) second(s)"
                Start-Sleep -Seconds $WaitSeconds
            }
            "$($Stage)Failed" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' failed"
                return $GraphRequest
            }
            "$($Stage)TimedOut" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' timed out"
                return $GraphRequest
            }
        }
    }
    until ($GraphRequest.uploadState -like "$($Stage)Success")
    Write-Verbose -Message "Intune service request for operation '$($Stage)' was successful with uploadState: $($GraphRequest.uploadState)"

    return $GraphRequest
}