param (
    [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud")]
    [Parameter(Mandatory = $false)]
    [string]$AzureEnvironment = "Global",

    [Parameter(Mandatory=$false, HelpMessage="The PermissionType parameter specifies whether the app registrations uses delegated or application permissions")] [ValidateSet('Application','Delegated')]
    [string]$PermissionType="Application",
    
    [Parameter(Mandatory=$False,HelpMessage="The OAuthClientId parameter is the Azure Application Id that this script uses to obtain the OAuth token.  Must be registered in Azure AD.")] 
    [string]$OAuthClientId = "fd9c6a9f-5be5-4771-8c8a-961f0cfbf423", #"ab125c77-d647-4524-82ee-b29bc5af1fc5",
    
    [Parameter(Mandatory=$False,HelpMessage="The OAuthTenantId parameter is the tenant Id where the application is registered (Must be in the same tenant as mailbox being accessed).")] 
    [string]$OAuthTenantId = "9101fc97-5be5-4438-a1d7-83e051e52057",
    
    [Parameter(Mandatory=$False,HelpMessage="The OAuthRedirectUri parameter is the redirect Uri of the Azure registered application.")] 
    [string]$OAuthRedirectUri = "http://localhost:8004",
    
    [Parameter(Mandatory=$False,HelpMessage="The OAuthSecretKey parameter is the the secret for the registered application.")] 
    [SecureString]$OAuthClientSecret,
    
    [Parameter(Mandatory=$False,HelpMessage="The OAuthCertificate parameter is the certificate for the registered application. Certificate auth requires MSAL libraries to be available.")] 
    [string]$OAuthCertificate = "24DCA626D48EE1383623FF26E6C8D852442D1DDC", #"6389EA02A19D671CAF8AFA03CA428FC7BB9AC16D",
  
    [Parameter(Mandatory=$False,HelpMessage="The CertificateStore parameter specifies the certificate store where the certificate is loaded.")] [ValidateSet("CurrentUser", "LocalMachine")]
     [string] $CertificateStore = "CurrentUser",

    [Parameter(Mandatory=$false)] [Array]$Scope= @("eDiscovery.ReadWrite.All"),

    [ValidateScript({ Test-Path $_ })]
    [Parameter(Mandatory = $true, HelpMessage="The OutputPath parameter specifies the path for the output data.")]
    [string] $OutputPath,

    [Parameter(Mandatory = $true, HelpMessage="The Mailbox parameter specifies the mailbox for the content search.")]
    [string] $Mailbox,

    [Parameter(Mandatory=$true,HelpMessage="The Operation parameter specifies the operation the script should perform.")] [ValidateSet("NewCase", "CheckEstimateStatus","LastEstimateStatistics","ListOperations","ExportData","CheckExportStatus","Download","AddPermission","GetPermission","StartSearch")]
    [string]$Operation,

    [string]$CaseId,

    [string]$SearchId

)

function Get-CloudServiceEndpoint {
    [CmdletBinding()]
    param(
        [string]$EndpointName
    )

    <#
        This shared function is used to get the endpoints for the Azure and Microsoft 365 services.
        It returns a PSCustomObject with the following properties:
            GraphApiEndpoint: The endpoint for the Microsoft Graph API
            ExchangeOnlineEndpoint: The endpoint for Exchange Online
            AutoDiscoverSecureName: The endpoint for Autodiscover
            AzureADEndpoint: The endpoint for Azure Active Directory
            EnvironmentName: The name of the Azure environment
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        # https://learn.microsoft.com/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
        switch ($EndpointName) {
            "Global" {
                $environmentName = "AzureCloud"
                $graphApiEndpoint = "https://graph.microsoft.com"
                $exchangeOnlineEndpoint = "https://outlook.office.com"
                $autodiscoverSecureName = "https://autodiscover-s.outlook.com"
                $azureADEndpoint = "https://login.microsoftonline.com"
                break
            }
            "USGovernmentL4" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "USGovernmentL5" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://dod-graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook-dod.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s-dod.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "ChinaCloud" {
                $environmentName = "AzureChinaCloud"
                $graphApiEndpoint = "https://microsoftgraph.chinacloudapi.cn"
                $exchangeOnlineEndpoint = "https://partner.outlook.cn"
                $autodiscoverSecureName = "https://autodiscover-s.partner.outlook.cn"
                $azureADEndpoint = "https://login.partner.microsoftonline.cn"
                break
            }
        }
    }
    end {
        return [PSCustomObject]@{
            EnvironmentName        = $environmentName
            GraphApiEndpoint       = $graphApiEndpoint
            ExchangeOnlineEndpoint = $exchangeOnlineEndpoint
            AutoDiscoverSecureName = $autodiscoverSecureName
            AzureADEndpoint        = $azureADEndpoint
        }
    }
}

function Get-NewJsonWebToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
        [ValidateSet("CurrentUser", "LocalMachine")][Parameter(Mandatory = $false)][string]$CertificateStore = "CurrentUser",
        [Parameter(Mandatory = $false)][string]$Issuer,
        [Parameter(Mandatory = $false)][string]$Audience,
        [Parameter(Mandatory = $false)][string]$Subject,
        [Parameter(Mandatory = $false)][int]$TokenLifetimeInSeconds = 3600,
        [ValidateSet("RS256", "RS384", "RS512")][Parameter(Mandatory = $false)][string]$SigningAlgorithm = "RS256"
    )

    <#
        Shared function to create a signed Json Web Token (JWT) by using a certificate.
        It is also possible to use a secret key to sign the token, but that is not supported in this function.
        The function returns the token as a string if successful, otherwise it returns $null.
        https://www.rfc-editor.org/rfc/rfc7519
        https://learn.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials
        https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        try {
            $certificate = Get-ChildItem Cert:\$CertificateStore\My\$CertificateThumbprint
            if ($certificate.HasPrivateKey) {
                $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
                # Base64url-encoded SHA-1 thumbprint of the X.509 certificate's DER encoding
                $x5t = [System.Convert]::ToBase64String($certificate.GetCertHash())
                $x5t = ((($x5t).Replace("\+", "-")).Replace("/", "_")).Replace("=", "")
                Write-Verbose "x5t is: $x5t"
            } else {
                Write-Verbose "We don't have a private key for certificate: $CertificateThumbprint and so cannot sign the token"
                return
            }
        } catch {
            Write-Verbose "Unable to import the certificate - Exception: $($Error[0].Exception.Message)"
            return
        }

        $header = [ordered]@{
            alg = $SigningAlgorithm
            typ = "JWT"
            x5t = $x5t
        }

        # "iat" (issued at) and "exp" (expiration time) must be UTC and in UNIX time format
        $payload = @{
            iat = [Math]::Round((Get-Date).ToUniversalTime().Subtract((Get-Date -Date "01/01/1970")).TotalSeconds)
            exp = [Math]::Round((Get-Date).ToUniversalTime().Subtract((Get-Date -Date "01/01/1970")).TotalSeconds) + $TokenLifetimeInSeconds
        }

        # Issuer, Audience and Subject are optional as per RFC 7519
        if (-not([System.String]::IsNullOrEmpty($Issuer))) {
            Write-Verbose "Issuer: $Issuer will be added to payload"
            $payload.Add("iss", $Issuer)
        }

        if (-not([System.String]::IsNullOrEmpty($Audience))) {
            Write-Verbose "Audience: $Audience will be added to payload"
            $payload.Add("aud", $Audience)
        }

        if (-not([System.String]::IsNullOrEmpty($Subject))) {
            Write-Verbose "Subject: $Subject will be added to payload"
            $payload.Add("sub", $Subject)
        }

        $headerJson = $header | ConvertTo-Json -Compress
        $payloadJson = $payload | ConvertTo-Json -Compress

        $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($headerJson)).Split("=")[0].Replace("+", "-").Replace("/", "_")
        $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($payloadJson)).Split("=")[0].Replace("+", "-").Replace("/", "_")

        $signatureInput = [System.Text.Encoding]::ASCII.GetBytes("$headerBase64.$payloadBase64")

        Write-Verbose "Header (Base64) is: $headerBase64"
        Write-Verbose "Payload (Base64) is: $payloadBase64"
        Write-Verbose "Signature input is: $signatureInput"

        $signingAlgorithmToUse = switch ($SigningAlgorithm) {
            ("RS384") { [Security.Cryptography.HashAlgorithmName]::SHA384 }
            ("RS512") { [Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        Write-Verbose "Signing the Json Web Token using: $SigningAlgorithm"

        $signature = $privateKey.SignData($signatureInput, $signingAlgorithmToUse, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signature = [Convert]::ToBase64String($signature).Split("=")[0].Replace("+", "-").Replace("/", "_")
    }
    end {
        if ((-not([System.String]::IsNullOrEmpty($headerBase64))) -and
            (-not([System.String]::IsNullOrEmpty($payloadBase64))) -and
            (-not([System.String]::IsNullOrEmpty($signature)))) {
            Write-Verbose "Returning Json Web Token"
            return ("$headerBase64.$payloadBase64.$signature")
        } else {
            Write-Verbose "Unable to create Json Web Token"
            return
        }
    }
}

function Get-ApplicationAccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$TenantID,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $false)][string]$TokenService = "oauth2/v2.0/token",
        [Parameter(Mandatory = $false)][switch]$CertificateBasedAuthentication,
        [Parameter(Mandatory = $true)][string]$Scope
    )

    <#
        Shared function to create an OAuth token by using a JWT or secret.
        If you want to use a certificate, set the CertificateBasedAuthentication switch and pass a JWT token as the Secret parameter.
        You can use the Get-NewJsonWebToken function to create a JWT token.
        If you want to use a secret, pass the secret as the Secret parameter.
        This function returns a PSCustomObject with the OAuth token, status and the time the token was created.
        If the request fails, the PSCustomObject will contain the exception message.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $oAuthTokenCallSuccess = $false
        $exceptionMessage = $null

        Write-Verbose "TenantID: $TenantID - ClientID: $ClientID - Endpoint: $Endpoint - TokenService: $TokenService - Scope: $Scope"
        $body = @{
            scope      = $Scope
            client_id  = $ClientID
            grant_type = "client_credentials"
        }

        if ($CertificateBasedAuthentication) {
            Write-Verbose "Function was called with CertificateBasedAuthentication switch"
            $body.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            $body.Add("client_assertion", $Secret)
        } else {
            Write-Verbose "Authentication is based on a secret"
            $body.Add("client_secret", $Secret)
        }

        $invokeRestMethodParams = @{
            ContentType = "application/x-www-form-urlencoded"
            Method      = "POST"
            Body        = $body # Create string by joining bodyList with '&'
            Uri         = "$Endpoint/$TenantID/$TokenService"
        }
    }
    process {
        try {
            Write-Verbose "Now calling the Invoke-RestMethod cmdlet to create an OAuth token"
            $oAuthToken = Invoke-RestMethod @invokeRestMethodParams
            Write-Verbose "Invoke-RestMethod call was successful"
            $oAuthTokenCallSuccess = $true
        } catch {
            Write-Host "We fail to create an OAuth token - Exception: $($_.Exception.Message)" -ForegroundColor Red
            $exceptionMessage = $_.Exception.Message
        }
    }
    end {
        return [PSCustomObject]@{
            OAuthToken           = $oAuthToken
            Successful           = $oAuthTokenCallSuccess
            ExceptionMessage     = $exceptionMessage
            LastTokenRefreshTime = (Get-Date)
        }
    }
}

function CheckTokenExpiry {
    param(
            $ApplicationInfo,
            [ref]$EWSService,
            [ref]$Token,
            [string]$Environment,
            $EWSOnlineURL,
            $AuthScope,
            $AzureADEndpoint
        )

    # if token is going to expire in next 5 min then refresh it
    if ($null -eq $script:tokenLastRefreshTime -or $script:tokenLastRefreshTime.AddMinutes(55) -lt (Get-Date)) {
        Write-Verbose "Requesting new OAuth token as the current token expires at $($script:tokenLastRefreshTime)."
        if($PermissionType -eq "Application") {
        $createOAuthTokenParams = @{
            TenantID                       = $ApplicationInfo.TenantID
            ClientID                       = $ApplicationInfo.ClientID
            Endpoint                       = $AzureADEndpoint
            CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($ApplicationInfo.CertificateThumbprint)))
            #Scope                          = $AuthScope
            Scope                           = $Script:GraphScope
        }

        # Check if we use an app secret or certificate by using regex to match Json Web Token (JWT)
        if ($ApplicationInfo.AppSecret -match "^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)") {
            $jwtParams = @{
                CertificateThumbprint = $ApplicationInfo.CertificateThumbprint
                CertificateStore      = $CertificateStore
                Issuer                = $ApplicationInfo.ClientID
                Audience              = "$AzureADEndpoint/$($ApplicationInfo.TenantID)/oauth2/v2.0/token"
                Subject               = $ApplicationInfo.ClientID
            }
            $jwt = Get-NewJsonWebToken @jwtParams

            if ($null -eq $jwt) {
                Write-Host "Unable to sign a new Json Web Token by using certificate: $($ApplicationInfo.CertificateThumbprint)" -ForegroundColor Red
                exit
            }

            $createOAuthTokenParams.Add("Secret", $jwt)
        } else {
            $createOAuthTokenParams.Add("Secret", $ApplicationInfo.AppSecret)
        }

        $oAuthReturnObject = Get-ApplicationAccessToken @createOAuthTokenParams
        if ($oAuthReturnObject.Successful -eq $false) {
            Write-Host ""
            Write-Host "Unable to refresh EWS OAuth token. Please review the error message below and re-run the script:" -ForegroundColor Red
            Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
            exit
        }
        Write-Host "Obtained a new token" -ForegroundColor Green
        $Script:Token = $oAuthReturnObject.OAuthToken.access_token
        $script:tokenLastRefreshTime = $oAuthReturnObject.LastTokenRefreshTime
        #return $oAuthReturnObject.OAuthToken.access_token
        }
        else {
            #$connectionSuccessful = $false
    
            # Request an authorization code from the Microsoft Azure Active Directory endpoint
            $redeemAuthCodeParams = @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ApplicationInfo.ClientID
                    scope         = $AuthScope
                    grant_type    = "refresh_token"
                    refresh_token =  $Script:RefreshToken
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $script:tokenLastRefreshTime = (Get-Date)
                $Script:RefreshToken = $tokens.refresh_token
                $Script:Token = $tokens.access_token
            } 
            else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
                exit
            }
        }
    }
    #return $Script:Token
}

function Get-DelegatedAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$AzureADEndpoint = "https://login.microsoftonline.com",
        [Parameter(Mandatory = $false)][string]$GraphApiUrl = "https://graph.microsoft.com",
        [Parameter(Mandatory = $false)][string]$Scope = "$($GraphApiUrl)//eDiscovery.Download.Read",
        [Parameter(Mandatory = $false)][string]$ClientID,
        [Parameter(Mandatory = $false)][string]$RedirectUri
    )

    <#
        This function is used to get an access token for the Azure Graph API by using the OAuth 2.0 authorization code flow
        with PKCE (Proof Key for Code Exchange). The OAuth 2.0 authorization code grant type, or auth code flow,
        enables a client application to obtain authorized access to protected resources like web APIs.
        The auth code flow requires a user-agent that supports redirection from the authorization server
        (the Microsoft identity platform) back to your application.

        More information about the auth code flow with PKCE can be found here:
        https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#protocol-details
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
       
        $responseType = "code" # Provides the code as a query string parameter on our redirect URI
        $prompt = "select_account" # We want to show the select account dialog
        $codeChallengeMethod = "S256" # The code challenge method is S256 (SHA256)
        $codeChallengeVerifier = Get-NewS256CodeChallengeVerifier
        $state = ([guid]::NewGuid()).Guid
        $connectionSuccessful = $false
    }
    process {
        $codeChallenge = $codeChallengeVerifier.CodeChallenge
        $codeVerifier = $codeChallengeVerifier.Verifier

        # Request an authorization code from the Microsoft Azure Active Directory endpoint
        $authCodeRequestUrl = "$AzureADEndpoint/organizations/oauth2/v2.0/authorize?client_id=$clientId" +
        "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&prompt=$prompt" +
        "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"

        Start-Process -FilePath $authCodeRequestUrl
        $authCodeResponse = Start-LocalListener

        if ($null -ne $authCodeResponse) {
            # Redeem the returned code for an access token
            $redeemAuthCodeParams = @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ClientID
                    scope         = $Scope
                    code          = ($($authCodeResponse.Split("=")[1]).Split("&")[0])
                    redirect_uri  = $RedirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeVerifier
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $connectionSuccessful = $true
            } else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
            }
        } else {
            Write-Host "Unable to acquire an authorization code from the Microsoft Azure Active Directory endpoint." -ForegroundColor Red
        }
    }
    end {
        if ($connectionSuccessful) {
            return [PSCustomObject]@{
                AccessToken = $tokens.access_token
                #RefreshToken = $tokens.refresh_token
                TenantId    = $TenantID #(Convert-JsonWebTokenToObject $tokens.id_token).Payload.tid
                LastTokenRefreshTime = (Get-Date)
                Successful           = $true
            }
        }
        exit
    }
}

function Convert-JsonWebTokenToObject {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern("^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)")][string]$Token
    )

    <#
        This function can be used to split a JSON web token (JWT) into its header, payload, and signature.
        The JWT is expected to be in the format of <header>.<payload>.<signature>.
        The function returns a PSCustomObject with the following properties:
            Header    - The header of the JWT
            Payload   - The payload of the JWT
            Signature - The signature of the JWT

            It returns $null if the JWT is not in the expected format or conversion fails.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        function ConvertJwtFromBase64StringWithoutPadding {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Jwt
            )
            $Jwt = ($Jwt.Replace("-", "+")).Replace("_", "/")
            switch ($Jwt.Length % 4) {
                0 { return [System.Convert]::FromBase64String($Jwt) }
                2 { return [System.Convert]::FromBase64String($Jwt + "==") }
                3 { return [System.Convert]::FromBase64String($Jwt + "=") }
                default { throw "The JWT is not a valid Base64 string." }
            }
        }
    }
    process {
        $tokenParts = $Token.Split(".")
        $tokenHeader = $tokenParts[0]
        $tokenPayload = $tokenParts[1]
        $tokenSignature = $tokenParts[2]

        Write-Verbose "Now processing token header..."
        $tokenHeaderDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenHeader))

        Write-Verbose "Now processing token payload..."
        $tokenPayloadDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenPayload))

        Write-Verbose "Now processing token signature..."
        $tokenSignatureDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenSignature))
    }
    end {
        if (($null -ne $tokenHeaderDecoded) -and
            ($null -ne $tokenPayloadDecoded) -and
            ($null -ne $tokenSignatureDecoded)) {
            Write-Verbose "Conversion of the token was successful"
            return [PSCustomObject]@{
                Header    = ($tokenHeaderDecoded | ConvertFrom-Json)
                Payload   = ($tokenPayloadDecoded | ConvertFrom-Json)
                Signature = $tokenSignatureDecoded
            }
        }

        Write-Verbose "Conversion of the token failed"
        return $null
    }
}

function Get-NewS256CodeChallengeVerifier {
    param()

    <#
        This function can be used to generate a new SHA256 code challenge and verifier following the PKCE specification.
        The Proof Key for Code Exchange (PKCE) extension describes a technique for public clients to mitigate the threat
        of having the authorization code intercepted. The technique involves the client first creating a secret,
        and then using that secret again when exchanging the authorization code for an access token.

        The function returns a PSCustomObject with the following properties:
        Verifier: The verifier that was generated
        CodeChallenge: The code challenge that was generated

        It returns $null if the code challenge and verifier generation fails.

        More information about the auth code flow with PKCE can be found here:
        https://www.rfc-editor.org/rfc/rfc7636
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $bytes = [System.Byte[]]::new(64)
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
    $b64String = [Convert]::ToBase64String($bytes)
    $verifier = (($b64String.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    $newMemoryStream = [System.IO.MemoryStream]::new()
    $newStreamWriter = [System.IO.StreamWriter]::new($newMemoryStream)
    $newStreamWriter.write($verifier)
    $newStreamWriter.Flush()
    $newMemoryStream.Position = 0
    $hash = Get-FileHash -InputStream $newMemoryStream | Select-Object Hash
    $hex = $hash.Hash

    $bytesArray = [byte[]]::new($hex.Length / 2)

    for ($i = 0; $i -lt $hex.Length; $i+=2) {
        $bytesArray[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }

    $base64Encoded = [Convert]::ToBase64String($bytesArray)
    $base64UrlEncoded = (($base64Encoded.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    if ((-not([System.String]::IsNullOrEmpty($verifier))) -and
        (-not([System.String]::IsNullOrEmpty(($base64UrlEncoded))))) {
        Write-Verbose "Verifier and CodeChallenge generated successfully"
        return [PSCustomObject]@{
            Verifier      = $verifier
            CodeChallenge = $base64UrlEncoded
        }
    }

    Write-Verbose "Verifier and CodeChallenge generation failed"
    return $null
}

function Start-LocalListener {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only non-destructive operations are performed in this function.')]
    param(
        [Parameter(Mandatory = $false)][int]$Port = 8004,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 60,
        [Parameter(Mandatory = $false)][string]$UrlContains = "code=",
        [Parameter(Mandatory = $false)][string]$ExpectedHttpMethod = "GET",
        [Parameter(Mandatory = $false)][string]$ResponseOutput = "Authentication complete. You can return to the application. Feel free to close this browser tab."
    )

    <#
        This function is used to start a local listener on the specified port (default: 8004).
        It will wait for the specified amount of seconds (default: 60) for a request to be made.
        The function will return the URL of the request that was made.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $url = $null
        $signalled = $false
        $stopwatch = New-Object System.Diagnostics.Stopwatch
        $listener = New-Object Net.HttpListener
    }
    process {
        $listener.Prefixes.add("http://localhost:$($Port)/")
        try {
            Write-Verbose "Starting listener..."
            Write-Verbose "Listening on port: $($Port)"
            Write-Verbose "Waiting $($TimeoutSeconds) seconds for request to be made to url that contains: $($UrlContains)"
            $stopwatch.Start()
            $listener.Start()

            while ($listener.IsListening) {
                $task = $listener.GetContextAsync()

                while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
                    if ($task.AsyncWaitHandle.WaitOne(100)) {
                        $signalled = $true
                        break
                    }
                    Start-Sleep -Milliseconds 100
                }

                if ($signalled) {
                    $context = $task.GetAwaiter().GetResult()
                    $request = $context.Request
                    $response = $context.Response
                    $url = $request.RawUrl
                    $content = [byte[]]@()

                    if (($url.Contains($UrlContains)) -and
                        ($request.HttpMethod -eq $ExpectedHttpMethod)) {
                        Write-Verbose "Request made to listener and url that was called is as expected. HTTP Method: $($request.HttpMethod)"
                        $content = [System.Text.Encoding]::UTF8.GetBytes($ResponseOutput)
                        $response.StatusCode = 200 # OK
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    } else {
                        Write-Verbose "Request made to listener but the url that was called is not as expected. URL: $($url)"
                        $response.StatusCode = 404 # Not Found
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    }
                } else {
                    Write-Verbose "Timeout of $($TimeoutSeconds) seconds reached..."
                    break
                }
            }
        } finally {
            Write-Verbose "Stopping listener..."
            Start-Sleep -Seconds 2
            $stopwatch.Stop()
            $listener.Stop()
        }
    }
    end {
        return $url
    }
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")][string]$Uri,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")][switch]$UseBasicParsing,
        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")][hashtable]$ParametersObject,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")][string]$OutFile
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        Write-VerboseErrorInformation
    }
}

function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)][string]$TargetUri
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server configuration detected"
            Write-Verbose $proxyObject.OriginalString
            return $true
        } else {
            Write-Verbose "No proxy server configuration detected"
            return $false
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
        return $false
    }
}

function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")][string]$Cmdlet
    )

    if ($null -ne $CurrentError.OriginInfo) {
        & $Cmdlet "Error Origin Info: $($CurrentError.OriginInfo.ToString())"
    }

    & $Cmdlet "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception.StackTrace)"
    } elseif ($null -ne $CurrentError.Exception) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        & $Cmdlet "Position Message: $($CurrentError.InvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        & $Cmdlet "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        & $Cmdlet "Script Stack: $($CurrentError.ScriptStackTrace)"
    }
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Write-HostErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Host"
}

function Get-OAuthToken {
    if($PermissionType -eq "Application") {
        if ([System.String]::IsNullOrEmpty($OAuthCertificate)) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($OAuthClientSecret)
            $Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $Script:applicationInfo.Add("AppSecret", $Secret)
        }
        else {
            $jwtParams = @{
                CertificateThumbprint = $OAuthCertificate
                CertificateStore      = $CertificateStore
                Issuer                = $OAuthClientId
                Audience              = "$azureADEndpoint/$OAuthTenantId/oauth2/v2.0/token"
                Subject               = $OAuthClientId
            }
            $jwt = Get-NewJsonWebToken @jwtParams
    
            if ($null -eq $jwt) {
                Write-Host "Unable to generate Json Web Token by using certificate: $CertificateThumbprint" -ForegroundColor Red
                exit
            }
    
            $Script:applicationInfo.Add("AppSecret", $jwt)
            $Script:applicationInfo.Add("CertificateThumbprint", $OAuthCertificate)
        }
    
        $createOAuthTokenParams = @{
            TenantID                       = $OAuthTenantId
            ClientID                       = $OAuthClientId
            Secret                         = $Script:applicationInfo.AppSecret
            Scope                          = $Script:GraphScope
            Endpoint                       = $azureADEndpoint
            CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($OAuthCertificate)))
        }
    
        #Create OAUTH token
        $oAuthReturnObject = Get-ApplicationAccessToken @createOAuthTokenParams
        if ($oAuthReturnObject.Successful -eq $false) {
            Write-Host ""
            Write-Host "Unable to fetch an OAuth token for accessing EWS. Please review the error message below and re-run the script:" -ForegroundColor Red
            Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
            exit
        }
        $Script:Token = $oAuthReturnObject.OAuthToken.access_token
        $Script:tokenLastRefreshTime = $oAuthReturnObject.LastTokenRefreshTime
    }
    elseif ($PermissionType -eq "Delegated") {
        if(-not(($Scope.Contains("email")))) {
            #$Scope += "email"
        }
        if(-not(($Scope.Contains("openid")))) {
            #$Scope += "openid"
        }
        if(-not(($Scope.Contains("offline_access")))) {
            #$Scope += "offline_access"
        }
        #$Script:GraphScope = "$($cloudService.GraphApiEndpoint)//$($Scope)"
        $oAuthReturnObject = Get-DelegatedAccessToken -AzureADEndpoint $cloudService.AzureADEndpoint -GraphApiUrl $cloudService.GraphApiEndpoint -Scope $Script:GraphScope -ClientID $OAuthClientId -RedirectUri $OAuthRedirectUri
        if ($oAuthReturnObject.Successful -eq $false) {
            Write-Host ""
            Write-Host "Unable to fetch an OAuth token for accessing EWS. Please review the error message below and re-run the script:" -ForegroundColor Red
            Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
            exit
        }    
        $Script:tokenLastRefreshTime = $oAuthReturnObject.LastTokenRefreshTime
        Write-Host $Script:Token -ForegroundColor green
        $Script:Token = $oAuthReturnObject.AccessToken
        $Script:RefreshToken = $oAuthReturnObject.RefreshToken
    }    
}

function Invoke-GraphApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [ValidateSet("v1.0", "beta")]
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = "v1.0",

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)")]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [int]$ExpectedStatusCode = 200,

        [Parameter(Mandatory = $true)]
        [string]$GraphApiUrl
    )

    <#
        This shared function is used to make requests to the Microsoft Graph API.
        It returns a PSCustomObject with the following properties:
            Content: The content of the response (converted from JSON to a PSCustomObject)
            Response: The full response object
            StatusCode: The status code of the response
            Successful: A boolean indicating whether the request was successful
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $successful = $false
        $content = $null
    }
    process {
        $graphApiRequestParams = @{
            Uri             = "$GraphApiUrl/$Endpoint/$($Query.TrimStart("/"))"
            Header          = @{ Authorization = "Bearer $AccessToken" }
            Method          = $Method
            ContentType     = $ContentType
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }

        if (-not([System.String]::IsNullOrEmpty($Body))) {
            Write-Verbose "Body: $Body"
            $graphApiRequestParams.Add("Body", $Body)
        }

        Write-Verbose "Graph API uri called: $($graphApiRequestParams.Uri)"
        Write-Verbose "Method: $($graphApiRequestParams.Method) ContentType: $($graphApiRequestParams.ContentType)"
        $graphApiResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $graphApiRequestParams

        if (($null -eq $graphApiResponse) -or
            ([System.String]::IsNullOrEmpty($graphApiResponse.StatusCode))) {
            Write-Verbose "Graph API request failed - no response"
        } elseif ($graphApiResponse.StatusCode -ne $ExpectedStatusCode) {
            Write-Verbose "Graph API status code: $($graphApiResponse.StatusCode) does not match expected status code: $ExpectedStatusCode"
        } else {
            Write-Verbose "Graph API request successful"
            $successful = $true
            $content = $graphApiResponse.Content | ConvertFrom-Json
        }
    }
    end {
        return [PSCustomObject]@{
            Content    = $content
            Response   = $graphApiResponse
            StatusCode = $graphApiResponse.StatusCode
            Successful = $successful
            Headers   = $graphApiResponse.Headers
        }
    }
}

if ($Mailbox -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') {
    Write-Host "The value provided for -Mailbox is not a valid SMTP address." -ForegroundColor Red
    exit
}
$cloudService = Get-CloudServiceEndpoint $AzureEnvironment
$azureADEndpoint = $cloudService.AzureADEndpoint

if($Operation -eq "Download"){
    $OAuthClientId = "fd9c6a9f-5be5-4771-8c8a-961f0cfbf423"
    $Script:GraphScope = "b26e684c-5068-4120-a679-64a5d2c909d9/.default"
}
else{
    $Script:GraphScope = "$($cloudService.GraphApiEndpoint)/.default"
}

$Script:applicationInfo = @{
    "TenantID" = $OAuthTenantId
    "ClientID" = $OAuthClientId
}

#Write-Host "Scope for the token is $($Script:GraphScope)" -ForegroundColor Green
Get-OAuthToken

switch($Operation){
    #Create a case
    "NewCase" {
        $RequestBody = @{
            displayName = "DEMO-Graph-Case-$((Get-Date).ToString("yyyyMMddHHmmss"))"
            description = "Demo case using Graph API"
        }

        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode = "201"
        }
        Write-Host "Creating a new case..." -ForegroundColor Cyan
        $Global:Case = Invoke-GraphApiRequest @GraphParams
        $CaseId = $Global:Case.Content.id
        Write-Host "CaseId: $($CaseId)" -ForegroundColor Green

        #Create a custodian
        $RequestBody = @{
            email = $Mailbox
        }
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/custodians"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode = "201"
        }
        Start-Sleep -Seconds 10
        Write-Host "Creating a custodian..." -ForegroundColor Cyan
        $Global:Custodian = Invoke-GraphApiRequest @GraphParams
        $CustodianId = $Global:Custodian.Content.id
        Write-Host "CustodianId: $($CustodianId)" -ForegroundColor Green

        #Create a custodian user source
        $RequestBody = @{
            email = $Mailbox
            includedSources = "mailbox"
        }
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/custodians/$($Global:Custodian.content.id)/userSources"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode = "201"
        }
        Start-Sleep -Seconds 10
        Write-Host "Creating a user source..." -ForegroundColor Cyan
        $Global:UserSource = Invoke-GraphApiRequest @GraphParams
        $UserSourceId = $Global:UserSource.Content.id
        Write-Host "UserSourceId: $($UserSourceId)" -ForegroundColor Green

        #Create a search
        $RequestBody = @{
            displayName = "EntireMailbox"
            description = "Return all items in the mailbox"
            dataSourceScopes = "allCaseCustodians"
        }
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/searches"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode = "201"
        }
        Start-Sleep -Seconds 10
        Write-Host "Creating a search..." -ForegroundColor Cyan
        $Global:Search = Invoke-GraphApiRequest @GraphParams
        $SearchId = $Global:Search.Content.id
        Write-Host "SearchId: $($SearchId)" -ForegroundColor Green

        #Start search
        Write-Host "Starting search..." -ForegroundColor Yellow
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/searches/$($SearchId)/estimateStatistics"
            Method              = "POST"
            ExpectedStatusCode = "202"
        }
        Start-Sleep -Seconds 10
        $global:EstimateStatistics = Invoke-GraphApiRequest @GraphParams
    }
    "StartSearch" {
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/searches/$($SearchId)/estimateStatistics"
            Method              = "POST"
            ExpectedStatusCode = "204"
        }
        $global:EstimateStatistics = Invoke-GraphApiRequest @GraphParams
    }
    "CheckEstimateStatus"{
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/operations/$($global:EstimateStatistics.Content.id)"
            Method              = "GET"
            ExpectedStatusCode = "200"
        }
        $Global:Operations = Invoke-GraphApiRequest @GraphParams
        Write-Host $Global:Operations.content.value
    }
    "LastEstimateStatistics" {
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/searches/$($SearchId)/lastEstimateStatisticsOperation"
            Method              = "GET"
            ExpectedStatusCode = "200"
        }
        $Global:SearchStatistics = Invoke-GraphApiRequest @GraphParams
        Write-Host $Global:SearchStatistics.content
    }
    "ExportData"{
        $RequestBody = @{
            displayName = "Export-Graph-Search-$((Get-Date).ToString("yyyyMMddHHmmss"))"
            exportFormat = "eml"
            exportCriteria = "searchHits"
        }
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/searches/$($SearchId)/exportResult"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode = "202"
        }
        $Global:Export = Invoke-GraphApiRequest @GraphParams
    }
    "ListOperations"{
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/operations"
            Method              = "GET"
            ExpectedStatusCode = "200"
        }
        $Global:Operations = Invoke-GraphApiRequest @GraphParams
        Write-Host $Global:Operations.content.value
    }
    "CheckExportStatus" {
        $Query = $Global:Export.Headers.Location.Replace("$($cloudService.graphApiEndpoint)/v1.0/", "")
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            #Query               = "security/cases/ediscoveryCases('ffa92671-2433-4424-9e3d-acaaf1add283')/operations('bdc457fc-3eb7-4b23-961c-05783fa5c0c8')"
            Query               = $Query
            Method              = "GET"
            ExpectedStatusCode = "200"
        }
        $Global:ExportOperation = Invoke-GraphApiRequest @GraphParams
        $Global:ExportOperation.content
    }
    "Download"{
        #$Global:ExportOperation.content.exportFileMetadata | ForEach-Object {
            #Write-Host "Downloading $($_.fileName)" -ForegroundColor Green
            $fileName = 'Export-Graph-Search-20250805150000_1.zip'
            Write-Host "Downloading $($fileName)" -ForegroundColor Green
            $downloadUrl = 'https://cus.proxyservice.ediscovery.office365.com/ediscovery/api/proxy/exportaedblobFileResult(eyJQYWNrYWdpbmdKb2JJZCI6IjQ2M2M1NmEzLTE0MWEtNGUzYy04YTJiLTA3OTcxOTZiOWIxMSIsIkNhc2VJZCI6IjgxZjc2OTU1LTcyYmItNGFhYi1iZmI5LWQxMDdkMDU4MTI0OSIsIkZpbGVOYW1lIjoiRXhwb3J0LUdyYXBoLVNlYXJjaC0yMDI1MDgwNTE1MDAwMF8xIiwiSXNEaXJlY3REb3dubG9hZFByb3h5Ijp0cnVlLCJFeHRlbnNpb24iOiIuemlwIiwiRm9sZGVyVHlwZSI6IlBhY2thZ2VzIn0)'
            #Invoke-WebRequest -Uri $_.downloadUrl -OutFile "$($OutputPath)\$($_.fileName)" -Headers @{"Authorization" = "Bearer $($Script:Token)"; "X-AllowWithAADToken"="true"}
            #Invoke-WebRequest -Uri $downloadURL -OutFile "$($OutputPath)\$($fileName)" -Headers @{"Authorization" = "Bearer $($Script:Token)"; "X-AllowWithAADToken"="true"}
        #}
        
        Add-Type -Path "C:\Program Files\WindowsPowerShell\Modules\AzureAD\2.0.2.182\Microsoft.Identity.Client.dll"

        $app = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create("fd9c6a9f-5be5-4771-8c8a-961f0cfbf423").WithRedirectUri("http://localhost").WithAuthority("https://login.microsoftonline.com/9101fc97-5be5-4438-a1d7-83e051e52057")
        $downloadApp = $app.Build()
$downloadScopes = New-Object System.Collections.Generic.List[string]
$appScope = "b26e684c-5068-4120-a679-64a5d2c909d9/.default"
$downloadScopes.Add($appScope)

$downloadtoken = $downloadApp.AcquireTokenInteractive($downloadScopes).WithLoginHint("magneto@thejimmartin.com").ExecuteAsync().Result
$downloadHeader = @{
'Content-Type'='application\json'
'Authorization'="Bearer $($downloadtoken.AccessToken)"
'X-AllowWithAADToken' = "true"
}
$directory = "C:\Temp\Output\"
#$filename = "Export-Graph-Search-20250702111918_1.zip"
#$downloadURL = "https://cus.proxyservice.ediscovery.office365.com/ediscovery/api/proxy/exportaedblobFileResult(eyJQYWNrYWdpbmdKb2JJZCI6ImJkYzQ1N2ZjLTNlYjctNGIyMy05NjFjLTA1NzgzZmE1YzBjOCIsIkNhc2VJZCI6ImZmYTkyNjcxLTI0MzMtNDQyNC05ZTNkLWFjYWFmMWFkZDI4MyIsIkZpbGVOYW1lIjoiRXhwb3J0LUdyYXBoLVNlYXJjaC0yMDI1MDcwMjExMTkxOF8xIiwiSXNEaXJlY3REb3dubG9hZFByb3h5Ijp0cnVlLCJFeHRlbnNpb24iOiIuemlwIiwiRm9sZGVyVHlwZSI6IlBhY2thZ2VzIn0=)"

Invoke-WebRequest -uri $downloadURL -OutFile "$($outpath)\$($filename)" -headers $downloadHeader


    }
    "AddPermission"{
        $RequestBody = @{
            recipientType = "user"
            smtpAddress = "thanos@thejimmartin.com"
            #ID = "1b1f7fe6-e37b-4032-a0c2-2b300e66557f"
            #displayName = "TJM-DownloadEDiscoveryExports"
        }
        $GraphParams = @{
            AccessToken         = $Script:Token
            GraphApiUrl         = $cloudService.graphApiEndpoint
            Query               = "security/cases/ediscoveryCases/$($CaseId)/caseMembers"
            Body                = $RequestBody | ConvertTo-Json -Depth 10
            Method              = "POST"
            ExpectedStatusCode  = "200"
            Endpoint            = "beta"
        }
        $Global:Permission = Invoke-GraphApiRequest @GraphParams
    }
"GetPermission"{
    $GraphParams = @{
        AccessToken         = $Script:Token
        GraphApiUrl         = $cloudService.graphApiEndpoint
        Query               = "security/cases/ediscoveryCases/$($CaseId)/caseMembers"
        Method              = "GET"
        ExpectedStatusCode  = "200"
        Endpoint            = "beta"
    }
    $Global:Permissions = Invoke-GraphApiRequest @GraphParams
    $Global:Permissions.content.value | ForEach-Object {
        Write-Host "$($_.displayName) - $($_.recipientType) - $($_.id)"
    }
}
}
<#
$GraphParams = @{
    AccessToken         = $Script:Token
    GraphApiUrl         = $cloudService.graphApiEndpoint
    Query               = "security/cases/ediscoverycases('da815019-1610-4876-a34e-fe1f77b3042a')/operations('b42a0cdb-152e-4590-9040-277b24d199b4')"
    #Query               = $ExportId
    Method              = "GET"
    ExpectedStatusCode = "200"
}
}
#$Global:ExportOperation = Invoke-GraphApiRequest @GraphParams
#$ExportOperation.Content

#GET /security/cases/ediscoveryCases/{ediscoveryCaseId}/searches/{ediscoverySearchId}/lastExportOperation

    #CheckTokenExpiry -Token ([ref]$Script:Token) -ApplicationInfo $Script:applicationInfo -AzureADEndpoint $azureADEndpoint -AuthScope $Script:GraphScope
#$Scope = "b26e684c-5068-4120-a679-64a5d2c909d9/.default"
<#
$Script:applicationInfo = @{
    "TenantID" = $OAuthTenantId
    "ClientID" = $OAuthClientId
}

#>
