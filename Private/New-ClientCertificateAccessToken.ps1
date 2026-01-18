function New-ClientCertificateAccessToken {
    <#
    .SYNOPSIS
        Requests an access token using the client certificate authentication flow.

    .DESCRIPTION
        Requests an access token using OAuth 2.0 client certificate authentication flow.
        This function creates a JWT client assertion signed with the certificate's private key
        and exchanges it for an access token from Microsoft Entra ID.

    .PARAMETER TenantID
        Tenant ID of the Entra ID tenant.

    .PARAMETER ClientID
        Application ID (Client ID) for an Entra ID service principal.

    .PARAMETER ClientCertificate
        X509Certificate2 object containing the client certificate with private key.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2026-01-18
        Updated:     2026-01-18

        Version history:
        1.0.0 - (2026-01-18) Script created with robust JWT creation and certificate validation
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Tenant ID of the Entra ID tenant.")]
        [ValidateNotNullOrEmpty()]
        [String]$TenantID,

        [parameter(Mandatory = $true, HelpMessage = "Application ID (Client ID) for an Entra ID service principal.")]
        [ValidateNotNullOrEmpty()]
        [String]$ClientID,

        [parameter(Mandatory = $true, HelpMessage = "X509Certificate2 object containing the client certificate with private key.")]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCertificate
    )
    Process {
        try {
            # Validate certificate has private key
            if (-not $ClientCertificate.HasPrivateKey) {
                throw "The provided certificate does not contain a private key. Client certificate authentication requires a certificate with a private key."
            }

            # Validate certificate is not expired
            $CurrentDate = Get-Date
            if ($ClientCertificate.NotBefore -gt $CurrentDate) {
                throw "The provided certificate is not yet valid. Valid from: $($ClientCertificate.NotBefore)"
            }
            if ($ClientCertificate.NotAfter -lt $CurrentDate) {
                throw "The provided certificate has expired. Expiration date: $($ClientCertificate.NotAfter)"
            }

            Write-Verbose -Message "Certificate validation successful"
            Write-Verbose -Message "Certificate Subject: $($ClientCertificate.Subject)"
            Write-Verbose -Message "Certificate Thumbprint: $($ClientCertificate.Thumbprint)"
            Write-Verbose -Message "Certificate Valid From: $($ClientCertificate.NotBefore) To: $($ClientCertificate.NotAfter)"

            # Create JWT header
            $JWTHeader = @{
                alg = "RS256"
                typ = "JWT"
                x5t = [Convert]::ToBase64String($ClientCertificate.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            }

            # Create JWT claims (payload)
            $Now = [Math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s"))
            $CreateDate = $Now
            $ExpiryDate = $CreateDate + 600  # Token valid for 10 minutes

            $JWTPayload = @{
                aud = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
                exp = $ExpiryDate
                iss = $ClientID
                jti = [Guid]::NewGuid().ToString()
                nbf = $CreateDate
                sub = $ClientID
                iat = $CreateDate
            }

            Write-Verbose -Message "JWT claims created with expiry: $($ExpiryDate)"

            # Encode header and payload
            $JWTHeaderEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $JWTPayloadEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_')

            # Create signature
            $JWTToSign = "$($JWTHeaderEncoded).$($JWTPayloadEncoded)"
            $JWTBytesToSign = [System.Text.Encoding]::UTF8.GetBytes($JWTToSign)

            # Get the private key and sign the JWT
            try {
                # Try to get RSA private key (works for both PowerShell 5.1 and 7.x)
                if ($ClientCertificate.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                    $RSA = $ClientCertificate.PrivateKey
                }
                elseif ($ClientCertificate.PrivateKey -is [System.Security.Cryptography.RSA]) {
                    $RSA = $ClientCertificate.PrivateKey
                }
                else {
                    # For newer certificate types, use GetRSAPrivateKey method
                    $RSA = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($ClientCertificate)
                }

                if ($null -eq $RSA) {
                    throw "Unable to retrieve RSA private key from certificate"
                }

                Write-Verbose -Message "Successfully retrieved RSA private key from certificate"

                # Sign the JWT
                $Signature = $RSA.SignData($JWTBytesToSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $SignatureEncoded = [Convert]::ToBase64String($Signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')

                Write-Verbose -Message "JWT signature created successfully"
            }
            catch {
                throw "Failed to sign JWT with certificate private key: $($_)"
            }

            # Create final JWT
            $JWT = "$($JWTHeaderEncoded).$($JWTPayloadEncoded).$($SignatureEncoded)"

            Write-Verbose -Message "JWT client assertion created successfully"

            # Request access token
            $TokenUri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
            $TokenBody = @{
                client_id = $ClientID
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                client_assertion = $JWT
                scope = "https://graph.microsoft.com/.default"
                grant_type = "client_credentials"
            }

            Write-Verbose -Message "Requesting access token from Entra ID"

            try {
                $TokenResponse = Invoke-RestMethod -Method Post -Uri $TokenUri -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

                # Validate the result
                if (-not $TokenResponse.access_token) {
                    throw "No access token was returned in the response"
                }

                Write-Verbose -Message "Access token retrieved successfully"

                # Calculate the ExpiresOn property based on the expires_in value
                $TokenResponse | Add-Member -MemberType NoteProperty -Name "ExpiresOn" -Value ((Get-Date).AddSeconds($TokenResponse.expires_in).ToUniversalTime()) -Force
                
                # Add Scopes property for permission tracking
                $TokenResponse | Add-Member -MemberType NoteProperty -Name "Scopes" -Value @("https://graph.microsoft.com/.default") -Force
                
                # Add AccessToken property for consistent access
                $TokenResponse | Add-Member -MemberType NoteProperty -Name "AccessToken" -Value $TokenResponse.access_token -Force

                # Set global variable
                $Global:AccessToken = $TokenResponse

                Write-Verbose -Message "Access token expires on: $($TokenResponse.ExpiresOn)"

                return $TokenResponse
            }
            catch {
                $ErrorMessage = "Failed to retrieve access token from Entra ID: $($_)"
                
                # Try to extract more detailed error information
                if ($_.Exception.Response) {
                    try {
                        $StreamReader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                        $ErrorDetails = $StreamReader.ReadToEnd()
                        $StreamReader.Close()
                        
                        if ($ErrorDetails) {
                            $ErrorObject = $ErrorDetails | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($ErrorObject.error_description) {
                                $ErrorMessage += " Details: $($ErrorObject.error_description)"
                            }
                            elseif ($ErrorObject.error) {
                                $ErrorMessage += " Error: $($ErrorObject.error)"
                            }
                        }
                    }
                    catch {
                        # If we can't parse the error, just use the original message
                    }
                }
                
                throw $ErrorMessage
            }
        }
        catch {
            throw "Error in client certificate authentication: $($_)"
        }
    }
}
