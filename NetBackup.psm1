
function Connect-NbuServer {
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

      [int]$Port = 1556,

      [switch]$SkipCertificateCheck
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
   
   #enable tls versions
   if ($PSVersionTable.PSVersion.Major -le 5) {
      [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
   }

   #Disable certificate check for trusted / expired cert
   if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -le 5)) {
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
      [System.Linq.Expressions.Expression]::Lambda(
          [System.Net.Security.RemoteCertificateValidationCallback],
          [System.Linq.Expressions.Expression]::Constant($true),
          [System.Linq.Expressions.ParameterExpression[]](
              [System.Linq.Expressions.Expression]::Parameter(
                  [object], 'sender'),
              [System.Linq.Expressions.Expression]::Parameter(
                  [X509Certificate], 'certificate'),
              [System.Linq.Expressions.Expression]::Parameter(
                  [System.Security.Cryptography.X509Certificates.X509Chain], 'chain'),
              [System.Linq.Expressions.Expression]::Parameter(
                  [System.Net.Security.SslPolicyErrors], 'sslPolicyErrors'))).
          Compile()      
   }

   if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
      $response = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body -SkipCertificateCheck
   }
   if (!($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
      $response = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body
   }

   if (($PSVersionTable.PSVersion.Major -le 5)) {
      $response = Invoke-RestMethod -Method POST -Uri $Uri -Headers $Headers -Body $Body
   }

   $Global:NBUconnection = "" | Select-Object -Property Server, Token, Username
   $Global:NBUconnection.Server = "https://$($Server):$Port/netbackup"
   $Global:NBUconnection.Token = $response.token
   $Global:NBUconnection.Username = $Username

   Write-Output $Global:NBUconnection
}


function Test-NbuConnection {
   [CmdletBinding()]
   param (
      [ValidateNotNullOrEmpty()]
      [string]$Server = $Global:NBUconnection.Server,
      
      [int]$Port = 1556,

      [switch]$SkipCertificateCheck
   )

   $Uri = $Server + "/ping"
    if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
        Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck
    }
    if (!($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
        Invoke-RestMethod -Method GET -Uri $Uri
    }

    if (($PSVersionTable.PSVersion.Major -le 5)) {
        Invoke-RestMethod -Method GET -Uri $Uri 
    }
}


function Get-NbuJob {
   [CmdletBinding(DefaultParameterSetName = "default")]
   param (
      
      [Parameter(ParameterSetName = "Id", Mandatory = $false)]
      [int[]]$JobId,

      
      [Parameter(ParameterSetName = "filter", Mandatory = $false)]
      [string]$Filter,

      [switch]$SkipCertificateCheck,
      
      [int]$Limit = 100,

      [Parameter(ParameterSetName = "default")][switch]$All 


      
   )
   
   begin {
      $Headers = @{
         "content-type"  = "application/vnd.netbackup+json;version=1.0"
         "Authorization" = $Global:NBUconnection.Token
      }

      
      $Body = @{
         "page[limit]" = $Limit                   # This changes the default page size
        
      }
      if ($Filter) {
         $Body.Add("filter", $Filter)
      }


     
   }
   process {
      if ($JobId) {
         foreach ($Job in $JobId) {            
            $Uri = $Global:NBUconnection.Server + "/admin/jobs/$Job"            
            
            if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
               [PScustomObject]$resp = Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers -Body $Body | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
            }
            else {
               [PScustomObject]$resp = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -Body $Body | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
            }
         }
      }
      else {
         $Uri = $Global:NBUconnection.Server + "/admin/jobs"

         if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
            [PScustomObject]$resp = Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers -Body $Body | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
         }
         else {
            [PScustomObject]$resp = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -Body $Body | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes 
         }
      }
      $resp | Add-Member -TypeName NetBackup.Jobs -PassThru
   }
}

function Get-NbuJobFileLists {
   [CmdletBinding()]
   param (
      [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
      [ValidateNotNullOrEmpty()][int[]]$JobId,
      [switch]$SkipCertificateCheck
   )
   
   begin {
      
      $Headers = @{
         "content-type"  = "application/vnd.netbackup+json;version=1.0"
         "Authorization" = $Global:NBUconnection.Token
      }
   }
   
   process {
      foreach ($Job in $JobId) {

         $Uri = $Global:NBUconnection.Server + "/admin/jobs/$Job/file-lists"
         if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
            Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
         }
         else {
            Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
         }
      }
   }
   
   end {
   }
}


function Get-NbuJobTryLogs {
   [CmdletBinding()]
   param (
      [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
      [ValidateNotNullOrEmpty()][int[]]$JobId,
      [switch]$SkipCertificateCheck      
   )
   
   begin {
      
      $Headers = @{
         "content-type"  = "application/vnd.netbackup+json;version=1.0"
         "Authorization" = $Global:NBUconnection.Token
      }
   }
   
   process {
      foreach ($Job in $JobId) {

         $Uri = $Global:NBUconnection.Server + "/admin/jobs/$Job/try-logs"
         if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
            Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
         }
         else {
            Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
         }
      }
   }
   
   end {
   }
}

function Get-NbuCatalogImage {
   [CmdletBinding(DefaultParameterSetName = "default")]
   param (
      [parameter(ParameterSetName = "backupId",ValueFromPipelineByPropertyName=$true)][string[]]$BackupId,
      # Parameter help description
      [Parameter(ParameterSetName = "filter")][string]$Filter,      
    
      [switch]$SkipCertificateCheck,      
      
      [int]$Limit = 100,
      
      [Parameter(ParameterSetName="default")][switch]$All 

   )

    
   begin {
      $Headers = @{
         "content-type"  = "application/vnd.netbackup+json;version=1.0"
         "Authorization" = $Global:NBUconnection.Token
      }

      $Body = @{
         "page[limit]" = $Limit                   # This changes the default page size
         
      }
      if ($Filter){
          $Body.Add("filter", $Filter)
      }

      [array]$resp = @()


   }
    
   process {
      if ($BackupId) {
         foreach ($Id in $BackupId) {            
            $Uri = $Global:NBUconnection.Server + "/catalog/images/$Id"            
          
            if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
               [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers -Body $Body
            }
            else {
               [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -Body $Body
            }
         }
      }
      else {
         $Uri = $Global:NBUconnection.Server + "/catalog/images"

         if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
            [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers -Body $Body
         }
         else {
            [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -Body $Body
         }
      }
       
   }

   end {
      [array]$collection = $resp.data.attributes

      for ($i = 0; $i -le ($collection.Count - 1); $i++) { 
         $collection[$i] | Add-Member -MemberType NoteProperty -Name "backupId" -Value $resp.data.id[$i]
      }
    
      $collection

   }

}



