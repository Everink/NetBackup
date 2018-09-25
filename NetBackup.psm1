
function Connect-NBServer {
   [CmdletBinding()]
   param (
      [parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Server = "localhost",
      
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
      $Password = $Credential.GetNetworkCredential().Password
   }

   $Uri = "https://$($Server):$Port/netbackup/login"

   $Headers = @{
      "content-type" = "application/vnd.netbackup+json;version=1.0"
   }

   $Body = @{
      #"domainType" = "vx"                                     
      #"domainName" = "mydomain"                               
      "userName"   = $Username                               
      "password"   = $Password
   } | ConvertTo-Json 
   
   
   Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body
   

}


