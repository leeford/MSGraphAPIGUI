


# Add required assemblies
Add-Type -AssemblyName System.Web, PresentationFramework, PresentationCore

function LoadXAML {

    param (
        
    )

    # Declare Objects
    $script:WPFObject = @{}

    # Load XAML File
    [xml]$xaml = Get-Content ".\MainWindow.xaml"

    # Feed XAML in to XMLNodeReader
    $XMLReader = (New-Object System.Xml.XmlNodeReader $xaml)

    # Create a Window Object
    $WindowObject = [Windows.Markup.XamlReader]::Load($XMLReader)

    $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")  | ForEach-Object {

        $script:WPFObject.Add($_.Name, $WindowObject.FindName($_.Name))

    }

}

function GetAuthToken {

    param (

    )

    # User permissions checked
    if ($script:WPFObject.userPermissionsRadioButton.IsChecked -eq $true) {

        # Check all required fields are valid
        ValidateTextBox "clientIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        ValidateTextBox "tenantIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        ValidateTextBox "redirectUriTextBox" "(.+)"
        ValidateTextBox "userPermissionsTextBox" "([a-zA-Z. ])+"

        if ($script:inputs.clientIdTextBox -eq $true -and $script:inputs.tenantIdTextBox -eq $true -and $script:inputs.redirectUriTextBox -eq $true -and $script:inputs.userPermissionsTextBox -eq $true) {

            # Get Issued Token for User
            $script:issuedToken = GetAuthTokenUser

        }
        else {

            Write-Warning "Not all fields populated to request token"
            $script:WPFObject.authStatusTextBox.Text = "Not all fields populated to request token"
            $script:WPFObject.authStatusTextBox.Foreground = "Red"
            $script:WPFObject.authStatusTextBox.Background = "Pink"

        }

    }

    # Application permissions selected
    if ($script:WPFObject.applicationPermissionsRadioButton.IsChecked -eq $true) {

        # Check all required fields are valid
        ValidateTextBox "clientIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        ValidateTextBox "tenantIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        ValidateTextBox "clientSecretPasswordBox" "(.+)"

        if ($script:inputs.clientIdTextBox -eq $true -and $script:inputs.tenantIdTextBox -eq $true -and $script:inputs.clientSecretPasswordBox -eq $true) {

            # Get Issued Token for Application
            $script:issuedToken = GetAuthTokenApplication

        }
        else {

            Write-Warning "Not all fields populated to request token"
            $script:WPFObject.authStatusTextBox.Text = "Not all fields populated to request token"
            $script:WPFObject.authStatusTextBox.Foreground = "Red"
            $script:WPFObject.authStatusTextBox.Background = "Pink"

        }
    }

    # If there is an issued token, set the token timer
    if ($script:issuedToken.access_token) {

        $script:tokenTimer = Get-Date

    }

}

function GetAuthCodeUser {
    param (


    )

    $clientId = [string]$script:WPFObject.clientIdTextBox.Text
    $tenantId = [string]$script:WPFObject.tenantIdTextBox.Text

    # Random State
    $state = Get-Random

    # Encode scope to fit inside query string
    $scope = [System.Web.HttpUtility]::UrlEncode($script:WPFObject.userPermissionsTextBox.Text)

    # Redirect URI (encode it to fit inside query string)
    $redirectUri = [System.Web.HttpUtility]::UrlEncode($script:WPFObject.redirectUriTextBox.Text)

    # Construct URI
    $uri = [uri]"https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize?client_id=$clientId&response_type=code&redirect_uri=$redirectUri&response_mode=query&scope=$scope&state=$state&prompt=login"

    # Create Window for User Sign-In
    $windowProperty = @{
        Width  = 500
        Height = 700
    }
    $signInWindow = New-Object System.Windows.Window -Property $windowProperty
    
    # Create WebBrowser for Window
    $browserProperty = @{
        Width  = 480
        Height = 680
    }
    $signInBrowser = New-Object System.Windows.Controls.WebBrowser -Property $browserProperty

    # Navigate Browser to sign-in page
    $signInBrowser.navigate($uri)
    
    # Create a condition to check after each page load
    $pageLoaded = {

        # Once a URL contains "code=*", close the Window
        if ($signInBrowser.Source -match "code=[^&]*") {

            # With the form closed and complete with the code, parse the query string

            $urlQueryString = [System.Uri]($signInBrowser.Source).Query
            $script:urlQueryValues = [System.Web.HttpUtility]::ParseQueryString($urlQueryString)

            $signInWindow.Close()

        }
    }

    # Add condition to document completed
    $signInBrowser.Add_LoadCompleted($pageLoaded)

    # Show Window
    $signInWindow.AddChild($signInBrowser)
    $signInWindow.ShowDialog()

    # Extract code and state from query string
    $authCode = $script:urlQueryValues.GetValues(($script:urlQueryValues.keys | Where-Object { $_ -eq "code" }))
    $returnedState = $script:urlQueryValues.GetValues(($script:urlQueryValues.keys | Where-Object { $_ -eq "state" }))

    # If auth code has been extracted and return state matches original state
    if ($authCode -and $state -match $returnedState) {

        return $authCode

    }
    else {

        Write-Error "Unable to obtain Auth Code or State mismatch!"

    }
    
}

function GetAuthTokenUser {
    param (

    )

    $clientId = [string]$script:WPFObject.clientIdTextBox.Text
    $tenantId = [string]$script:WPFObject.tenantIdTextBox.Text
    $scope = [string]$script:WPFObject.userPermissionsTextBox.Text
    
    # Get Auth Code needed for Token
    $authCode = GetAuthCodeUser

    # Construct URI
    $uri = [uri]"https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id    = $clientId
        scope        = "$scope offline_access" # Add offline_access to scope to ensure refresh_token is issued
        code         = $authCode[1]
        redirect_uri = $script:WPFObject.redirectUriTextBox.Text
        grant_type   = "authorization_code"
    }

    $authDate = Get-Date

    # Get OAuth 2.0 Token
    $tokenRequest = try {

        Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

    }
    catch [System.Net.WebException] {

        Write-Warning "Exception was caught: $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Text = "$authDate - $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Foreground = "Red"
        $script:WPFObject.authStatusTextBox.Background = "Pink"
        $script:WPFObject.runQueryButton.IsEnabled = $false
    
    }

    # If token request was a success
    if ($tokenRequest.StatusCode -eq 200) {

        # Update UI
        $script:WPFObject.authStatusTextBox.Text = "$authDate - User Token Acquired"
        $script:WPFObject.authStatusTextBox.Foreground = "DarkGreen"
        $script:WPFObject.authStatusTextBox.Background = "LightGreen"
        $script:WPFObject.runQueryButton.IsEnabled = $true
        $script:WPFObject.grantedUserPermissionsTextBox.Text = $tokenRequest.Content | ConvertFrom-Json | Select-Object -ExpandProperty scope

        return $tokenRequest.Content | ConvertFrom-Json
        
    }

}

function GetAuthTokenUserRefresh {

    param (

    )

    $clientId = [string]$script:WPFObject.clientIdTextBox.Text
    $tenantId = [string]$script:WPFObject.tenantIdTextBox.Text
    $scope = [string]$script:WPFObject.userPermissionsTextBox.Text

    # Construct URI
    $uri = [uri]"https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id    = $clientId
        scope        = "$scope offline_access" # Add offline_access to scope to ensure refresh_token is issued
        redirect_uri = $script:WPFObject.redirectUriTextBox.Text
        grant_type   = "refresh_token"
        refresh_token = $script:issuedToken.refresh_token
    }

    $authDate = Get-Date

    # Get OAuth 2.0 Token
    $tokenRequest = try {

        Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

    }
    catch [System.Net.WebException] {

        Write-Warning "Exception was caught: $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Text = "$authDate - $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Foreground = "Red"
        $script:WPFObject.authStatusTextBox.Background = "Pink"
        $script:WPFObject.runQueryButton.IsEnabled = $false
    
    }

    # If token request was a success
    if ($tokenRequest.StatusCode -eq 200) {

        # Update UI
        $script:WPFObject.authStatusTextBox.Text = "$authDate - Refreshed User Token Acquired"
        $script:WPFObject.authStatusTextBox.Foreground = "DarkGreen"
        $script:WPFObject.authStatusTextBox.Background = "LightGreen"
        $script:WPFObject.runQueryButton.IsEnabled = $true
        $script:WPFObject.grantedUserPermissionsTextBox.Text = $tokenRequest.Content | ConvertFrom-Json | Select-Object -ExpandProperty scope

        return $tokenRequest.Content | ConvertFrom-Json
        
    }

}

function GetAuthTokenApplication {

    param (

    )

    $clientId = [string]$script:WPFObject.clientIdTextBox.Text
    $tenantId = [string]$script:WPFObject.tenantIdTextBox.Text
    $clientSecret = [string]$script:WPFObject.clientSecretPasswordBox.Password

    # Construct URI
    $uri = [uri]"https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }

    $authDate = Get-Date

    # Get OAuth 2.0 Token
    $tokenRequest = try {

        Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

    }
    catch [System.Net.WebException] {

        Write-Warning "Exception was caught: $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Text = "$authDate - $($_.Exception.Message)"
        $script:WPFObject.authStatusTextBox.Foreground = "Red"
        $script:WPFObject.authStatusTextBox.Background = "Pink"
        $script:WPFObject.runQueryButton.IsEnabled = $false
    
    }

    # If token request was a success
    if ($tokenRequest.StatusCode -eq 200) {

        # Update UI
        $script:WPFObject.authStatusTextBox.Text = "$authDate - Application Token Acquired"
        $script:WPFObject.authStatusTextBox.Foreground = "DarkGreen"
        $script:WPFObject.authStatusTextBox.Background = "LightGreen"
        $script:WPFObject.runQueryButton.IsEnabled = $true

        return $tokenRequest.Content | ConvertFrom-Json
        
    }

}

function InvokeGraphAPICall {
    param (
        

    )

    # Calculate current token age
    $tokenAge = New-TimeSpan $script:tokenTimer (Get-Date)

    # Check token has not expired
    if ($tokenAge.TotalSeconds -gt 3500) {

        Write-Warning "Token Expired!"

        # If last token issued included a refresh token
        if($script:issuedToken.refresh_token) {

            # Get new token using refresh token
            GetAuthTokenUserRefresh

        # Otherwise authenticate without
        } else {

            GetAuthToken

        }

    }        
        
    # Construct headers
    $Headers = @{"Authorization" = "Bearer $($script:issuedToken.access_token)"}
    Foreach ($i in 1..5) {

        $currentRequestKey = "requestKey$($i)TextBox"
        $currentRequestValue = "requestValue$($i)TextBox"

        if ($script:WPFObject.$currentRequestKey.Text -and $script:WPFObject.$currentRequestValue.Text) {

            $Headers.Add($script:WPFObject.$currentRequestKey.Text, $script:WPFObject.$currentRequestValue.Text)

        }

    }

    $apiCall = try {

        # If there is a body (and it's not a GET), use it
        if ($body -and $method -ne "GET") {

            Invoke-WebRequest -Method $script:WPFObject.httpMethodComboBox.SelectedItem -Uri $script:WPFObject.httpQueryTextBox.Text -ContentType "application/json" -Headers $Headers -Body $script:WPFObject.httpRequestBodyTextBox.Text -ErrorAction Stop

        }
        else {

            Invoke-WebRequest -Method $script:WPFObject.httpMethodComboBox.SelectedItem -Uri $script:WPFObject.httpQueryTextBox.Text -ContentType "application/json" -Headers $Headers -ErrorAction Stop

        }
        

    }
    catch [System.Net.WebException] {

        $querydate = Get-Date
        Write-Warning "Exception was caught: $($_.Exception.Message)"
        $script:WPFObject.httpResponseStatusTextBox.Text = "$querydate - $($_.Exception.Message)"
        $script:WPFObject.httpResponseStatusTextBox.Foreground = "Red"
        $script:WPFObject.httpResponseStatusTextBox.Background = "Pink"

    }
    
    return $apiCall

}

function ValidateTextBox {
    param (
        
        [Parameter(mandatory = $true)][string]$textbox,
        [Parameter(mandatory = $true)][string]$regex

    )
    
    # Remove existing validation from hashtable
    $script:inputs.Remove($textbox)

    if ($script:WPFObject.$textbox.Text -match $regex -or $script:WPFObject.$textbox.Password -match $regex) {

        $script:WPFObject.$textbox.BorderBrush = "Green"
        $script:inputs.Add($textbox, $true)

    }
    else {

        $script:WPFObject.$textbox.BorderBrush = "Red"
        $script:inputs.Add($textbox, $false)

    }

}

$script:inputs = @{}

# Load XAML File
LoadXAML

# Populate UI
$httpMethods = @("GET", "POST", "PUT", "PATCH", "DELETE")
$script:WPFObject.httpMethodComboBox.ItemsSource = $httpMethods
$script:WPFObject.httpMethodComboBox.SelectedItem = "GET"

# Authenticate Clicked
$script:WPFObject.authButton.add_Click( {

        GetAuthToken

    })

# Run Query Clicked
$script:WPFObject.runQueryButton.add_Click( {

        # Validate http query
        ValidateTextBox "httpQueryTextBox" "https:\/\/.[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)"

        if ($script:issuedToken.access_token -and $script:inputs.httpQueryTextBox -eq $true) {

            $apiCall = InvokeGraphAPICall

            # If there is content
            if ($apiCall.Content) {

                $script:WPFObject.httpResponseContentTextBox.Text = $apiCall.Content | ConvertFrom-Json -ErrorAction SilentlyContinue | ConvertTo-Json -ErrorAction SilentlyContinue
                $script:WPFObject.exportResponseContentButton.IsEnabled = $true

            }
            else {

                $script:WPFObject.httpResponseContentTextBox.Text = $null
                $script:WPFObject.exportResponseContentButton.IsEnabled = $false

            }
            
            # If there is a status code
            if ($apiCall.StatusCode) {
                
                $querydate = Get-Date
                $script:WPFObject.httpResponseStatusTextBox.Text = "$querydate - $($apiCall.StatusCode) - $($apiCall.StatusDescription)"
                $script:WPFObject.httpResponseStatusTextBox.Foreground = "DarkGreen"
                $script:WPFObject.httpResponseStatusTextBox.Background = "LightGreen"

            }

            # If there are headers
            if ($apiCall.Headers) {

                $script:WPFObject.httpResponseHeadersTextBox.Text = $apiCall.Headers | Out-String

            }
            else {

                $script:WPFObject.httpResponseHeadersTextBox.Text = $null

            }

        }

    })

# Validate client/application ID
$script:WPFObject.clientIdTextBox.add_TextChanged( {

        ValidateTextBox "clientIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"

    })

# Validate tenant ID
$script:WPFObject.tenantIdTextBox.add_TextChanged( {

        ValidateTextBox "tenantIdTextBox" "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"

    })

# Validate redirect URI
$script:WPFObject.redirectUriTextBox.add_TextChanged( {

        ValidateTextBox "redirectUriTextBox" "(.+)"

    })

# Validate secret
$script:WPFObject.clientSecretPasswordBox.add_PasswordChanged( {

        ValidateTextBox "clientSecretPasswordBox" "(.+)"

    })

# Validate user permissions
$script:WPFObject.userPermissionsTextBox.add_TextChanged( {

        ValidateTextBox "userPermissionsTextBox" "([a-zA-Z. ])+"

    })

# Validate http query URI
$script:WPFObject.httpQueryTextBox.add_TextChanged( {

        ValidateTextBox "httpQueryTextBox" "https:\/\/.[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)"

    })

# Disable Request body if using GET
$script:WPFObject.httpMethodComboBox.add_SelectionChanged( {

        if ($script:WPFObject.httpMethodComboBox.SelectedItem -eq "GET") {

            $script:WPFObject.httpRequestBodyTabItem.IsEnabled = $false
            $script:WPFObject.httpRequestBodyTextBox.IsEnabled = $false

        }
        else {

            $script:WPFObject.httpRequestBodyTabItem.IsEnabled = $true
            $script:WPFObject.httpRequestBodyTextBox.IsEnabled = $true

        }

    })

# Export Content Clicked
$script:WPFObject.exportResponseContentButton.add_Click( {

        $saveAs = New-Object Microsoft.Win32.SaveFileDialog
        $saveAs.Filter = "All Files|*.*"
        $saveAs.ShowDialog()

        $script:WPFObject.httpResponseContentTextBox.Text | Out-File $saveAs.Filename

    })

# Show WPF MainWindow
$script:WPFObject.MainWindow.ShowDialog() | Out-Null