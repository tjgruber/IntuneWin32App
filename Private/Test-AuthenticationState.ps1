function Test-AuthenticationState {
    <#
    .SYNOPSIS
        Validates that the authentication state is ready for Graph API calls.

    .DESCRIPTION
        Performs a lightweight check to ensure the global authentication variables are properly initialized.
        This function does NOT validate token expiration or perform any refresh operations.
        It only checks that the required global variables exist and are not null/empty.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2025-01-18
        Updated:     2025-01-18

        Version history:
        1.0.0 - (2025-01-18) Function created for lightweight authentication state validation
    #>
    Process {
        # Check for authentication header
        if ($null -eq $Global:AuthenticationHeader) {
            return $false
        }

        # Check for access token object
        if ($null -eq $Global:AccessToken) {
            return $false
        }

        # Check for tenant ID
        if ([string]::IsNullOrEmpty($Global:AccessTokenTenantID)) {
            return $false
        }

        # All required global variables are present
        return $true
    }
}
