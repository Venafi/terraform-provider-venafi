# To disable parameter positioning (introduced in PowerShell 3.0)
[CmdletBinding(PositionalBinding=$false)]
param (
    [Parameter(Mandatory=$true)][string]$WORK_PATH,
    [Parameter(Mandatory=$true)][string]$WEB_NAME,
    [Parameter(Mandatory=$true)][string]$ASSET_NAME,
    [Parameter(Mandatory=$true)][string]$BINDING_PORT,
    [Parameter(Mandatory=$true)][string]$BINDING_IP,
    [int]$SSL_FLAG = $null,
    [Parameter(Mandatory=$true)][string]$EXECUTE = ""
)

$IIS_BINDINGS_PATH = "IIS:\\SslBindings"
$CERT_LOCAL_MACHINE_PATH = "Cert:\LocalMachine\My"
$CERT_PATH = "${WORK_PATH}\${ASSET_NAME}.p12"

function init($sslFlags) {

    # Adding certificate to local store
    $pfx = Import-PfxCertificate -FilePath $CERT_PATH -CertStoreLocation "$CERT_LOCAL_MACHINE_PATH"
    $certThumbprint = $pfx.Thumbprint

    # Creates a new web binding and adds the certificate for it
    if(!$PSBoundParameters.ContainsKey('sslFlags')){
        New-WebBinding -Name "$WEB_NAME" -IPAddress $BINDING_IP -Port $BINDING_PORT -Protocol "https"
        (Get-WebBinding -Name "$WEB_NAME" -Port $BINDING_PORT -Protocol "https").AddSslCertificate($certThumbprint, "My")
    } else {
        New-WebBinding -Name "$WEB_NAME" -IPAddress $BINDING_IP -Port $BINDING_PORT -Protocol "https" -Hostheader $ASSET_NAME -SslFlags $sslFlags
        (Get-WebBinding -Name "$WEB_NAME" -Port $BINDING_PORT -Protocol "https" -Hostheader $ASSET_NAME).AddSslCertificate($certThumbprint, "My")
    }
    

    # Let's compare current Windows version to see if we can handle the new HSTS feature introduced in Windows Server 2019 (10.0.17763)
    $winVer = [System.Environment]::OSVersion.Version
    $majorVer = [int]$winVer.Major
    $minorVer = [int]$winVer.Minor
    $buildNum = [int]$winVer.Build
    
    # currentIIS >= HSTS supported version
    if($majorVer -gt 10 -or ($majorVer -eq 10 -and $minorVer -eq 0 -and $buildNum -ge 17763)){
        # Updating default values fot HSTS in order to redirect http to https
        Import-Module IISAdministration
        Reset-IISServerManager -Confirm:$false
        Start-IISCommitDelay

        $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
        $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="$WEB_NAME"}
        $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $true
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 31536000
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "includeSubDomains" -AttributeValue $true
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $true

        Stop-IISCommitDelay
        Remove-Module IISAdministration
    }
}
function destroy($sslFlags) {
    if(!$PSBoundParameters.ContainsKey('sslFlags')){
        Remove-WebBinding -Name "$WEB_NAME" -Port $BINDING_PORT -Protocol "https"
        Remove-Item -Path "$IIS_BINDINGS_PATH\$BINDING_IP!$BINDING_PORT"
    } else {
        Remove-WebBinding -Name "$WEB_NAME" -Port $BINDING_PORT -Protocol "https" -Hostheader "$ASSET_NAME"
        if($sslFlags -eq 0){
            Remove-Item -Path "$IIS_BINDINGS_PATH\$BINDING_IP!$BINDING_PORT"
        } elseif ($sslFlags -eq 1){
            Remove-Item -Path "$IIS_BINDINGS_PATH\!$BINDING_PORT!$ASSET_NAME"
        }
        
    }
    

    $certObject = Get-ChildItem -path cert:\LocalMachine\My | Where-Object{$_.Subject -like "CN=$ASSET_NAME"} | Select-Object -First 1
    $certThumbprint = $certObject.Thumbprint
    $certPath = "$CERT_LOCAL_MACHINE_PATH\${certThumbprint}"
    Remove-Item -Path $certPath

    $winVer = [System.Environment]::OSVersion.Version
    $majorVer = [int]$winVer.Major
    $minorVer = [int]$winVer.Minor
    $buildNum = [int]$winVer.Build

    if($majorVer -gt 10 -or ($majorVer -eq 10 -and $minorVer -eq 0 -and $buildNum -ge 17763)){
        Import-Module IISAdministration
        Reset-IISServerManager -Confirm:$false
        Start-IISCommitDelay
    
        $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
        $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="$WEB_NAME"}
        $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $false
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 0
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "includeSubDomains" -AttributeValue $false
        Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $false
    
        Stop-IISCommitDelay
        Remove-Module IISAdministration
    }
}

if($EXECUTE -ceq "init"){
    if($PSBoundParameters.ContainsKey('SSL_FLAG')){
        init -sslFlags $SSL_FLAG
    } else {
        init
    }
} elseif ($EXECUTE -ceq "destroy") {
    if($PSBoundParameters.ContainsKey('SSL_FLAG')){
        destroy -sslFlags $SSL_FLAG
    } else {
        destroy
    }
} else {
    Write-Host("No configuration was applied")
}