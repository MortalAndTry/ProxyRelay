$uri = 'http://127.0.0.1:8000/PowerShell/' 
$username = 'whatever' # unimportant
$password = 'whatever' # unimportant 
 
$secure = ConvertTo-SecureString $password -AsPlainText -Force 
$creds  = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $secure) 
$option = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck 
 
$params = @{ 
    ConfigurationName = "Microsoft.Exchange" 
    Authentication    = "Basic" 
    ConnectionUri     = $uri 
    Credential        = $creds 
    SessionOption     = $option 
    AllowRedirection  = $ture 
} 
$session = New-PSSession @params 
 


#$pwd=convertto-securestring Password123 -asplaintext -force
#$command = {New-Mailbox -UserPrincipalName testuser1@server.cd  -OrganizationalUnit server.cd/Users -Alias testuser1 -Name testuser1 -DisplayName testuser1 -Password $args[0];}
$command = {Get-Mailbox}


Invoke-Command -Session $session -ScriptBlock $command  -ArgumentList $pwd