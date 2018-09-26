
function Connect-NBUserver {
   [CmdletBinding()]
   param (
      [parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Server,
      
      [parameter(Mandatory = $true, ParameterSetName = "Username")]
      [ValidateNotNullOrEmpty()]
      [String]$Username,

      [parameter(Mandatory = $true, ParameterSetName = "Username")]
      [ValidateNotNullOrEmpty()]
      [SecureString]$Password,

      [Parameter(Mandatory = $true, ParameterSetName = "Credential")]
      [ValidateNotNullOrEmpty()]
      [Management.Automation.PSCredential]$Credential,

      [int]$Port = 1556
   )
   
   if ($PSCmdlet.ParameterSetName -eq "Credential") {
      $Username = $Credential.UserName
      $JSONPassword = $Credential.GetNetworkCredential().Password 
   }

   if ($PSCmdlet.ParameterSetName -eq "Username") {
      $JSONPassword = (New-Object System.Management.Automation.PSCredential("username", $Password)).GetNetworkCredential().Password
   }

   $Uri = "https://$($Server):$Port/netbackup/login"

   $Headers = @{
      "content-type" = "application/vnd.netbackup+json;version=1.0"
   }

   if ($Username -like "*@*.*" ) {      
      $preat = ($Username -split "@")[0]
      $postat = ($Username -split "@")[1]
      
      $Body = @{
         #"domainType" = "vx"                                     
         "domainName" = ($postat -split "\.")[0]
         "userName"   = $preat                               
         "password"   = $JSONPassword
      } | ConvertTo-Json
   }
   else {
      $Body = @{
         #"domainType" = "vx"                                     
         #"domainName" = "mydomain"                               
         "userName" = $Username                               
         "password" = $JSONPassword
      } | ConvertTo-Json 
   }
   
   $response = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body -SkipCertificateCheck
   
   $Global:NBUconnection = "" | Select-Object -Property Server,Token,Username
   $Global:NBUconnection.Server = $Server
   $Global:NBUconnection.Token = $response.token
   $Global:NBUconnection.Username = $Username

   Write-Output $Global:NBUconnection
}


