# Client Certificate Authentication Examples

# This sample demonstrates how to authenticate to Microsoft Graph using client certificate authentication
# for service principal (app-only) scenarios.

# Prerequisites:
# 1. An Azure AD app registration with API permissions (DeviceManagementApps.ReadWrite.All, etc.)
# 2. A certificate uploaded to the app registration in Azure AD
# 3. The certificate with private key installed in the certificate store or exported as PFX

# ==============================================================================
# Example 1: Using a certificate from the certificate store (Current User)
# ==============================================================================

# Find certificate by thumbprint
$CertThumbprint = "ABC123DEF456..." # Replace with your certificate thumbprint
$Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $CertThumbprint }

if ($Certificate) {
    Write-Host "Certificate found: $($Certificate.Subject)" -ForegroundColor Green
    Write-Host "Valid from: $($Certificate.NotBefore) to: $($Certificate.NotAfter)" -ForegroundColor Green
    
    # Connect using client certificate
    Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate -Verbose
}
else {
    Write-Warning "Certificate with thumbprint $CertThumbprint not found in CurrentUser\My store"
}


# ==============================================================================
# Example 2: Using a certificate from the certificate store (Local Machine)
# ==============================================================================

# Note: Requires elevated permissions to access LocalMachine store
$CertThumbprint = "ABC123DEF456..." # Replace with your certificate thumbprint
$Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $CertThumbprint }

if ($Certificate) {
    Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate
}


# ==============================================================================
# Example 3: Loading certificate from a PFX file
# ==============================================================================

# Load certificate from PFX file with password
$PfxPath = "C:\Certificates\MyAppCert.pfx"
$PfxPassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force

if (Test-Path $PfxPath) {
    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword)
    
    # Verify certificate has private key
    if ($Certificate.HasPrivateKey) {
        Write-Host "Certificate loaded successfully with private key" -ForegroundColor Green
        Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate
    }
    else {
        Write-Warning "Certificate does not contain a private key. Ensure you exported the certificate with the private key."
    }
}
else {
    Write-Warning "PFX file not found at: $PfxPath"
}


# ==============================================================================
# Example 4: Using certificate from Azure Key Vault
# ==============================================================================

# Prerequisites: Az.KeyVault module installed and authenticated
# Import-Module Az.KeyVault
# Connect-AzAccount

<#
$VaultName = "MyKeyVault"
$CertificateName = "MyAppCert"

# Get certificate from Key Vault
$KeyVaultCert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
$Secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $KeyVaultCert.Name -AsPlainText

# Convert secret to certificate
$CertBytes = [Convert]::FromBase64String($Secret)
$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertBytes)

Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate
#>


# ==============================================================================
# Example 5: Finding certificates by subject name
# ==============================================================================

$SubjectName = "CN=MyAppCertificate"
$Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $SubjectName } | Select-Object -First 1

if ($Certificate) {
    Write-Host "Found certificate: $($Certificate.Subject)" -ForegroundColor Green
    Write-Host "Thumbprint: $($Certificate.Thumbprint)" -ForegroundColor Cyan
    Write-Host "Issuer: $($Certificate.Issuer)" -ForegroundColor Cyan
    
    Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate
}


# ==============================================================================
# Example 6: Checking certificate validity before connecting
# ==============================================================================

function Test-CertificateValidity {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    $Now = Get-Date
    $IsValid = $true
    $Messages = @()
    
    # Check if certificate has private key
    if (-not $Certificate.HasPrivateKey) {
        $IsValid = $false
        $Messages += "Certificate does not contain a private key"
    }
    
    # Check if certificate is expired
    if ($Certificate.NotAfter -lt $Now) {
        $IsValid = $false
        $Messages += "Certificate expired on: $($Certificate.NotAfter)"
    }
    
    # Check if certificate is not yet valid
    if ($Certificate.NotBefore -gt $Now) {
        $IsValid = $false
        $Messages += "Certificate not valid until: $($Certificate.NotBefore)"
    }
    
    # Warn if certificate expires soon (within 30 days)
    $DaysUntilExpiry = ($Certificate.NotAfter - $Now).Days
    if ($DaysUntilExpiry -lt 30 -and $DaysUntilExpiry -gt 0) {
        $Messages += "WARNING: Certificate expires in $DaysUntilExpiry days"
    }
    
    return [PSCustomObject]@{
        IsValid = $IsValid
        Messages = $Messages
        Certificate = $Certificate
    }
}

# Usage
$CertThumbprint = "ABC123DEF456..."
$Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $CertThumbprint }

if ($Certificate) {
    $ValidationResult = Test-CertificateValidity -Certificate $Certificate
    
    if ($ValidationResult.IsValid) {
        Write-Host "Certificate validation successful" -ForegroundColor Green
        foreach ($Message in $ValidationResult.Messages) {
            Write-Host $Message -ForegroundColor Yellow
        }
        
        Connect-MSIntuneGraph -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -ClientCert $Certificate
    }
    else {
        Write-Error "Certificate validation failed:"
        foreach ($Message in $ValidationResult.Messages) {
            Write-Error $Message
        }
    }
}


# ==============================================================================
# Example 7: Complete workflow with error handling
# ==============================================================================

function Connect-WithCertificate {
    param(
        [string]$TenantID,
        [string]$ClientID,
        [string]$CertThumbprint
    )
    
    try {
        # Find certificate
        Write-Verbose "Looking for certificate with thumbprint: $CertThumbprint"
        $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My" -ErrorAction Stop | 
            Where-Object { $_.Thumbprint -eq $CertThumbprint }
        
        if (-not $Certificate) {
            throw "Certificate with thumbprint $CertThumbprint not found in certificate store"
        }
        
        Write-Verbose "Certificate found: $($Certificate.Subject)"
        
        # Validate certificate
        if (-not $Certificate.HasPrivateKey) {
            throw "Certificate does not contain a private key"
        }
        
        $Now = Get-Date
        if ($Certificate.NotAfter -lt $Now) {
            throw "Certificate expired on: $($Certificate.NotAfter)"
        }
        
        if ($Certificate.NotBefore -gt $Now) {
            throw "Certificate not yet valid. Valid from: $($Certificate.NotBefore)"
        }
        
        Write-Verbose "Certificate validation passed"
        
        # Connect to Microsoft Graph
        Write-Host "Connecting to Microsoft Graph using client certificate..." -ForegroundColor Cyan
        Connect-MSIntuneGraph -TenantID $TenantID -ClientID $ClientID -ClientCert $Certificate -Verbose
        
        Write-Host "Successfully authenticated to Microsoft Graph" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to authenticate: $($_)"
        return $false
    }
}

# Usage
$ConnectResult = Connect-WithCertificate -TenantID "tenant.onmicrosoft.com" -ClientID "00000000-0000-0000-0000-000000000000" -CertThumbprint "ABC123DEF456..."

if ($ConnectResult) {
    # Proceed with Intune operations
    $Apps = Get-IntuneWin32App
    Write-Host "Retrieved $($Apps.Count) Win32 apps" -ForegroundColor Green
}


# ==============================================================================
# Additional Notes
# ==============================================================================

<#
Certificate Requirements:
- The certificate must contain a private key
- The certificate must be valid (not expired and within validity period)
- The certificate must be uploaded to the Azure AD app registration
- The certificate must use RSA key algorithm
- Recommended: Use certificates from a trusted CA for production

Azure AD App Registration Setup:
1. Navigate to Azure AD > App registrations > Your app
2. Go to "Certificates & secrets"
3. Upload your certificate (.cer or .pem file - public key only)
4. Note the thumbprint shown in Azure AD
5. Ensure API permissions are granted (DeviceManagementApps.ReadWrite.All, etc.)
6. Grant admin consent for the permissions

Certificate Store Locations:
- Cert:\CurrentUser\My - Current user's personal certificate store
- Cert:\LocalMachine\My - Local machine's personal certificate store (requires elevation)
- Cert:\CurrentUser\Root - Trusted root certificates
- Cert:\LocalMachine\Root - Trusted root certificates (system-wide)

Troubleshooting:
- If authentication fails, use -Verbose parameter to see detailed error messages
- Verify certificate thumbprint matches exactly in Azure AD
- Ensure certificate has not expired
- Verify the certificate contains the private key
- Check that API permissions are granted and consented
#>
