

<#
.SYNOPSIS
Connect to a specified NetBackup Server.

.DESCRIPTION
Connect to a NetBackup server and retrieve a token for other NetBackup commands.

.PARAMETER Server
Specifies the NetBackup masterserver

.PARAMETER Username
Specifies the username to use to connect to the server. Use either username or a credential object.

.PARAMETER Password
The password, needs to be securestring object. if connecting with a username you will be asked to supply the password

.PARAMETER Credential
The credential object to authenticate to the NetBackup server.

.PARAMETER Port
The port to connect to, default is 1556, the PBX port.

.PARAMETER SkipCredentialCheck
To skip checking for self-signed certs or other invalid certs.

.INPUTS
None. You cannot pipe objects to Add-Extension.

.OUTPUTS
Outsputs a global variable NBUconnection

.EXAMPLE
C:\PS> Connect-NbuServer -Server netbackup.domain.com -SkipCredentialCheck

.EXAMPLE
C:\PS> Connect-NbuServer -Server netback.domain.com

#>
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


<#
.SYNOPSIS
Tests the connection to the gateway service from the client and returns the master server time in milliseconds.

.DESCRIPTION
Tests the connection to the gateway service from the client and returns the master server time in milliseconds.

.PARAMETER Server
Specifies the NetBackup masterserver. tries to use the global variable: Global:NBUConnection.Server

.PARAMETER Port
The port to connect to, default is 1556, the PBX port.

.PARAMETER SkipCredentialCheck
To skip checking for self-signed certs or other invalid certs, only used for PowerShell version 6.x

.INPUTS
None. You cannot pipe objects to Add-Extension.

.OUTPUTS
NetBackup masterserver time in milliseconds

.EXAMPLE
C:\PS> Test-NbuConnection
1538133805320

#>
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



<#
.SYNOPSIS
Gets the list of jobs based on specified filters.

.DESCRIPTION
Gets the list of jobs based on specified filters.

.PARAMETER JobId
Gets the netbackup job based on the JobId(s)

.PARAMETER Filter
Specifies filters according to OData standards

.PARAMETER SkipCredentialCheck
To skip checking for self-signed certs or other invalid certs, only used for PowerShell version 6.x

.PARAMETER Limit
Ammount of jobs to return. Default value is 100

.INPUTS
None. You cannot pipe objects to Add-Extension.

.OUTPUTS
Netbackup.Jobs object

.EXAMPLE
C:\PS> Get-NbuJob -JobId "2","3"
Returns netback jobs with a jobId of 2 or 3

.EXAMPLE
C:\PS> Get-NbuJob -Filter "state eq 'DONE'" -SkipCertificateCheck
Returns netbackup jobs with a state of DONE

.EXAMPLE
C:\PS> Get-NbuJob -Filter "status ne 0"  -SkipCertificateCheck
Returns netbackup jobs with a status not equal to 0

.EXAMPLE
C:\PS> Get-NbuJob -Filter "clientName eq 'server.domain.com'" -Limit 20
Returns maximum of 20 netbackup jobs from which the client is equal to server.domain.com
#>
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
      if ($resp) {
         $resp | Add-Member -TypeName NetBackup.Jobs -PassThru
      }
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



<#
.SYNOPSIS
Get the list of images based on specified filters.

.DESCRIPTION
Get the list of images based on specified filters.
If no filters are specified, information for the last 100 images made within the last 24 hours is returned

.PARAMETER backupId
Gets the netbackup job based on the backupId(s)

.PARAMETER Filter
Specifies filters according to OData standards

.PARAMETER SkipCredentialCheck
To skip checking for self-signed certs or other invalid certs, only used for PowerShell version 6.x

.PARAMETER Limit
Ammount of jobs to return. Default value is 100

.INPUTS
Accepts pipeline input byproperty backupId

.OUTPUTS
List of catalog images

.EXAMPLE
C:\PS> Get-NbuCatalogImage -BackupId "server.domain.com_1537968156","server2.domain.com_1538110836"
Returns catalog images by backupId

.EXAMPLE
C:\PS> Get-NbuJob -JobId 2,3 | Get-NbuCatalogImage
Returns catalog images based on the backupId of netbackupJobs with JobId 2 and 3

.EXAMPLE
C:\PS> Get-NbuCatalogImage -Filter "clientName eq 'server.domain.com' and policyName eq 'FS_WIN_test'" -Limit 5
Returns a maximum of 5 catalog images where clientname is equal to server.domain.com AND policyname is equal to FS_WIN_test

.EXAMPLE
C:\PS>  Get-NBUjob -Filter "status eq 0" | Where-Object {$_.backupId -ne ""} | Get-NbuCatalogImage
Returns the catalog images from all netbackup jobs that were succesfull, and have a backupId
This will exclude jobs like image cleanups, since they have no backup ID
#>
function Get-NbuCatalogImage {
   [CmdletBinding(DefaultParameterSetName = "default")]
   param (
      [parameter(ParameterSetName = "backupId", ValueFromPipelineByPropertyName = $true)] 
      [ValidateNotNullOrEmpty()]     
      [string[]]$BackupId,
      # Parameter help description
      [Parameter(ParameterSetName = "filter")][string]$Filter,      
    
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
      if ($PSCmdlet.ParameterSetName -eq "backupId") {         
         Write-Verbose "BackupId found: $backupId... processing foreach in case of array by parameter input"
         foreach ($Id in $BackupId) {            
            Write-Verbose "Inside foreach loop. processing backupId: $Id"
            if ($Id -eq "") {Write-Verbose "BackupId empty, try filtering these out. skipping this"}
            else {
               $Uri = $Global:NBUconnection.Server + "/catalog/images/$Id"            
          
               if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
                  [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers -Body $Body
               }
               else {
                  [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -Body $Body
               }
            }


         }
      }      
      else {
         Write-Verbose "NOT parameterset backupId"
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

function Get-NbuVMwareCatalogImage {
   [CmdletBinding()]
   param (
      [Parameter(ValueFromPipelineByPropertyName = $true)][string[]]$backupId        
   )
    
   begin {
      $Headers = @{
         "content-type"  = "application/vnd.netbackup+json;version=1.0"
         "Authorization" = $Global:NBUconnection.Token
      }
      [array]$resp = @()
   }
    
   process {
       
      foreach ($Id in $BackupId) {            
         $Uri = $Global:NBUconnection.Server + "/catalog/vmware-images/$Id"            
      
         if (($SkipCertificateCheck.IsPresent) -and ($PSVersionTable.PSVersion.Major -eq 6)) {
            [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -SkipCertificateCheck -Headers $Headers
         }
         else {
            [array]$resp += Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
         }
      }
       
   }

    
   end {
       $resp
   }
}


