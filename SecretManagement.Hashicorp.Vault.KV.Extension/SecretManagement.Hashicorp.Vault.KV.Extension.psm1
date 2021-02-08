#region Private Helper Functions

class HashicorpVaultKV
{
    static [String] $VaultServer = $env:VAULT_ADDR
    static [String] $VaultToken = $env:VAULT_TOKEN
    static [String] $VaultNameSpace = $env:VAULT_NAMESPACE
    static [String] $VaultAPIVersion = 'v1'
    static [String] $KVVersion = 'v2'
    static [hashtable] $AppRole = @{ Role_Id = $env:VAULT_ROLEID; Secret_Id = $env:VAULT_SECRETID }
}

function Connect-Vault 
{
    [CmdletBinding()]
    param (        
    )

    if (-not [HashicorpVaultKV]::VaultToken)
    {
        if ([HashicorpVaultKV]::AppRole)
        {
            try 
            {            
                $uri = "https://{0}/{1}/{2}auth/approle/login" -f @(
                    [HashicorpVaultKV]::VaultServer, 
                    [HashicorpVaultKV]::VaultAPIVersion, 
                    [HashicorpVaultKV]::VaultNameSpace
                )    
            
                $body = [hashtable]@{
                    role_id   = [HashicorpVaultKV]::AppRole.Role_Id
                    secret_id = [HashicorpVaultKV]::AppRole.Secret_Id
                }

                $response = Invoke-RestMethod -Method Post -Uri $uri.ToLower() -Body $body -TimeoutSec 5 -ErrorAction Stop
                [HashicorpVaultKV]::VaultToken = $response.auth.client_token
            }
            catch 
            {
                Write-Error -Exception $_
            }
        }        
    }  
    
}

function Invoke-CustomWebRequest
{
    <#
    .SYNOPSIS
    Custom Web Request function to support non standard methods
    #>
    [Cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [String]$Uri,

        [Parameter(Mandatory)]
        [object]$Headers,

        [Parameter(Mandatory)]
        [String]$Method
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    $Client = New-Object -TypeName System.Net.Http.HttpClient
    $Client.DefaultRequestHeaders.Accept.Add($Headers['Accept'])
    $Request = New-Object -TypeName System.Net.Http.HttpRequestMessage
    $Request.Method = $Method
    $Request.Headers.Add('X-Vault-Token', $Headers['X-Vault-Token'])
    $Request.Headers.Add('ContentType', $Headers['Content-type'])
    $Request.RequestUri = $Uri

    $Result = $Client.SendAsync($Request)
    $StatusCode = $Result.Result.StatusCode
    if ($StatusCode -eq 'OK')
    {
        $Result.Result.Content.ReadAsStringAsync().Result | ConvertFrom-Json
    }
    else
    {
        Throw "$StatusCode for $Method on $Uri"
    }
    $Client.Dispose()
    $Request.Dispose()
}

function Test-VaultVariable
{
    <#
    .SYNOPSIS
    Ensures that all Static Variables are configured
    #>
    [Cmdletbinding()]
    param (
        [Parameter()]
        [hashtable]$Arguments
    )

    foreach ($k in $Arguments.GetEnumerator())
    {
        if ($null -eq [HashicorpVaultKV]::$($k.Key) -or [HashicorpVaultKV]::$($k.Key) -ne $($k.Key))
        {
            [HashicorpVaultKV]::$($k.Key) = $k.Value
        }
    }
}

function New-VaultAPIHeader
{
    <#
    .SYNOPSIS
    Creates a header for an API call
    #>
    @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'X-Vault-Token' = "$([HashicorpVaultKV]::VaultToken)"
    }
}

function New-VaultAPIBody
{
    <#
    .SYNOPSIS
    Creates the Body of an API call for Set-Secret
    #>
    [CmdletBinding()]
    param (
        [Cmdletbinding()]
        [hashtable]$Data
    )

    if ([HashicorpVaultKV]::KVVersion -eq 'v1')
    {
        $Tempbody = $Data
    }
    elseif ([HashicorpVaultKV]::KVVersion -eq 'v2')
    {
        $Tempbody = @{
            data = $Data
        }
    }

    $OutputBody = $Tempbody | ConvertTo-Json
    return $OutputBody
}

function Resolve-VaultSecretPath
{
    <#
    .SYNOPSIS
    Walks the Hashicorp KV strucutre to list secrets
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$VaultName,

        [Parameter()]
        [String]$Path
    )

    $Data = (Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Path).data
    
    foreach ($k in $Data.Keys)
    {
        $KeyPath = $Path, $k -join '/'

        if ($KeyPath.endswith('/'))
        {
            $ResolveSplat = @{
                VaultName = $VaultName
                Path      = $KeyPath.Trim('/')
            }            
            Resolve-VaultSecretPath @ResolveSplat
        }
        else
        {
            $KeyPath.TrimStart('/')
        }
    }
}


function Invoke-VaultAPIQuery
{
    <#
    .SYNOPSIS
    Abstracts logic for which methods, and API calls should be done.
    #>
    [CmdletBinding()]
    param (
        [Cmdletbinding()]
        [String]$VaultName,

        [Cmdletbinding()]
        [String]$SecretName,

        [Cmdletbinding()]
        [object]$SecretValue
    )

    try
    {
        $Headers = New-VaultAPIHeader
        $serverURI = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)/$([HashicorpVaultKV]::VaultNameSpace)"
        $baseURI = "$serverURI/$VaultName"
        $CallStack = (Get-PSCallStack)[1]
        $CallingCommand = $CallStack.Command
        $CallingVerb, $CallingNoun = ($CallingCommand -split '-')

        if ([HashicorpVaultKV]::KVVersion -eq 'v1')
        {
            $Uri = "$baseURI/$SecretName"
            $listuri = "$baseURI/$SecretName"
        }
        elseif ([HashicorpVaultKV]::KVVersion -eq 'v2')
        {
            $Uri = "$baseURI/data/$SecretName"
            $listuri = "$baseURI/metadata/$SecretName"
        }

        switch ($CallingVerb)
        {
            Get
            {
                if ($CallingNoun -eq 'SecretInfo')
                {
                    $Method = 'LIST'
                    $Uri = $listuri
                }
                else
                {
                    $Method = 'GET'
                }
            }
            Set
            {
                $Method = 'POST'
                if ($SecretName -match '/')
                {
                    $Name = $($SecretName -split '/')[-1]
                }
                else
                {
                    $Name = $SecretName
                }
                $Body = New-VaultAPIBody -data @{
                    $Name = $SecretValue
                }
            }
            Test
            {
                $Method = 'GET'
                $Uri = "$serverURI/sys/health", "$serverURI/sys/mounts"
            }
            Remove
            {
                $Method = 'DELETE'
                # Deletes the secret like a KV version1
                # KV version2 supports versions, which can't be implemented yet.
                # TODO provide a argument for type of action to take on KV v2
                $Uri = $listuri
            }
            Resolve
            {
                $Method = 'LIST'
                $Uri = $listuri
            }
        }

        $VaultSplat = @{
            URI     = $Uri
            Method  = $Method
            Headers = $Headers
        }
        if ($null -ne $Body)
        {
            $VaultSplat['Body'] = $Body 
        }

        if ($Method -eq 'List')
        {
            Invoke-CustomWebRequest @VaultSplat
        }
        elseif ($CallingVerb -eq 'Test')
        {
            foreach ($u in $($Uri -split ','))
            {
                $VaultSplat['URI'] = $u
                Invoke-RestMethod @VaultSplat
            }
        }
        else
        {
            Invoke-RestMethod @VaultSplat
        }
    }
    catch
    {
        throw
    }
    finally
    {
        #Probably unecessary, but precautionary.
        $VaultSplat, $listuri, $Uri, $Method, $Headers, $Body = $null
    }
}

#endregion Private Helper Functions


#region Public functions

function Get-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process
    {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        if ($Name -match '/')
        {
            $SecretName = $($Name -split '/')[-1]
        }
        else
        {
            $SecretName = $Name
        }

        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name

        switch ([HashicorpVaultKV]::KVVersion)
        {
            'v1'
            {
                $Secret = $SecretData.data
                $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                continue
            }
            'v2'
            {
                $Secret = $SecretData.data.data
                $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                continue
            }
            default
            {
                throw 'Unknown KeyVaule version' 
            }
        }

        return $SecretObject
    }
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $Filter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process
    {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters

        $Filter = "*$Filter"
        $VaultSecrets = Resolve-VaultSecretPath -VaultName $VaultName
        $VaultSecrets |
        Where-Object {
            $PSItem -like $Filter 
        } |
        ForEach-Object {
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                "$PSItem",
                'String',
                $VaultName)
        }
    }
}

function Set-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [object] $Secret,

        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process
    {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters

        switch ($Secret.GetType())
        {
            'String'
            {
                $SecretValue = $Secret
            }
            'SecureString'
            {
                $SecretValue = $Secret | ConvertFrom-SecureString -AsPlainText
            }
            'PSCredential'
            {
                $SecretValue = $Secret.Password | ConvertFrom-SecureString -AsPlainText
            }
            default
            {
                throw "Unsupported secret type: $($Secret.GetType().Name)"
            }
        }

        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name -SecretValue $SecretValue

        #$? represents the success/fail of the last execution
        if (-not $?)
        {
            throw $SecretData
        }
        return $?
    }
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [String] $VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process
    {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name

        #$? represents the success/fail of the last execution
        if (-not $?)
        {
            throw $SecretData
        }

        return $?
    }
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [String] $VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process
    {
        $ErrorActionPreference = 'STOP'
        Test-VaultVariable -Arguments $AdditionalParameters

        if ($null -eq [HashicorpVaultKV]::VaultServer)
        {
            [HashicorpVaultKV]::VaultServer = Read-Host -Prompt 'Please provide the URL for the HashiCorp Vault (Example: https://myvault.domain.local)'
        }

        if ($null -eq [HashicorpVaultKV]::VaultToken)
        {
            [HashicorpVaultKV]::VaultToken = (Read-Host -Prompt 'Provide Vault Token' -AsSecureString | ConvertFrom-SecureString -AsPlainText )
        }

        try
        {
            $VaultHealth = (Invoke-VaultAPIQuery -VaultName $VaultName)
        }
        catch
        {
            throw "Something occured while communicating with $([HashicorpVaultKV]::VaultServer). Doublecheck the URL"
        }

        if ($VaultHealth[0].sealed -eq 'True')
        {
            Throw "The Hashicorp Vault at $([HashicorpVaultKV]::VaultServer) is sealed"
        }

        #This should return $null if the vault doesn't exist
        $SelectedVault = $VaultHealth[1].$("$VaultName/")
        if ($null -eq $SelectedVault)
        {
            Throw "$VaultName does not exist at $([HashicorpVaultKV]::VaultServer)"
        }

        return $?
    }
}

#endregion Public functions