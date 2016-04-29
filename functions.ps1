<#
.SYNOPSIS
   Functions for FindEncryptedFiles.ps1, which includes a script by Bart Kuppens. 
#>

#Function to write to Log Files.
function LogWrite {
         
         Param ([string]$logstring)
         Add-content $Logfile -value $logstring
}

function EncryptedFileFound{

#Encrypted file - Send the data to CryptPath file.
Write-Output "Encrypted File" >> $CryptPath
Write-Output "$File" >> $CryptPath
Write-Output  $Object >> $CryptPath
Write-Output "==================================================== " >> $CryptPath

#Send the Data to Log File, which will be sent to the administrator by e-mail.

LogWrite "Encrypted: $File"
LogWrite "Entropy: $($Object.Entroopia)"
LogWrite "Chi: $($Object.Chi)"
LogWrite "Mean: $($Object.Mean)"
LogWrite "Monte: $($Object.Monte)"
LogWrite "Serial: $($Object.Serial)"

}
<#
.SYNOPSIS
   Checks for disconnected sessions and logs off the disconnected user sessions.

.DESCRIPTION
   Checks for disconnected sessions and logs off the disconnected user sessions.

.NOTES
   File Name: Logoff-DisconnectedSession.ps1
   Author   : Bart Kuppens
   Version  : 1.0

.EXAMPLE
   PS > .\Logoff-DisconnectedSession.ps1
#>
function Get-Sessions
{
   $queryResults = query session
   $starters = New-Object psobject -Property @{"SessionName" = 0; "UserName" = 0; "ID" = 0; "State" = 0; "Type" = 0; "Device" = 0;}
   foreach ($result in $queryResults)
   {
      try
      {
         if($result.trim().substring(0, $result.trim().indexof(" ")) -eq "SESSIONNAME")
         {
            $starters.UserName = $result.indexof("USERNAME");
            $starters.ID = $result.indexof("ID");
            $starters.State = $result.indexof("STATE");
            $starters.Type = $result.indexof("TYPE");
            $starters.Device = $result.indexof("DEVICE")
            continue;
         }

         New-Object psobject -Property @{
            "SessionName" = $result.trim().substring(0, $result.trim().indexof(" ")).trim(">");
            "Username" = $result.Substring($starters.Username, $result.IndexOf(" ", $starters.Username) - $starters.Username);
            "ID" = $result.Substring($result.IndexOf(" ", $starters.Username), $starters.ID - $result.IndexOf(" ", $starters.Username) + 2).trim();
            "State" = $result.Substring($starters.State, $result.IndexOf(" ", $starters.State)-$starters.State).trim();
            "Type" = $result.Substring($starters.Type, $starters.Device - $starters.Type).trim();
            "Device" = $result.Substring($starters.Device).trim()
         }

      } 
      catch 
      {
         $e = $_;
         Write-Output "ERROR: " + $e.PSMessageDetails
      }
   }
}

#Disable the offending user Function. If Disconnect is enabled and an encrypted file is found, the security log is searched for the offending user. 
#If a match is found, the user is stored, otherwise a new search without the filepath is carried out. 
#The SMB Access of the offending user is blocked, SMB Sessions are closed, and if the user is on the same machine (terminal), the user is logged off from the machine.
#An E-mail is sent to the Administrator of the offence.

function DisableUser
{

if ($Disconnect) {
LogWrite "Encrypted Files Found - Looking for the offending user" 


    try  { 
  

    $events = Get-WinEvent -ErrorAction Stop -FilterHashtable @{logname='security';id=4656; data=$FilePath} |
    Select-Object -Property timecreated, @{label='username';expression={$_.properties[1].value}} | Select-Object -First 1
    $Owner = $events.username

    }

    catch [Exception] {
        if ($_.Exception -match "No events were found that match the specified selection criteria") {
        LogWrite "No events found - Looking for the last event of 4656";

        $events = Get-WinEvent -ErrorAction Stop -FilterHashtable @{logname='security';id=4656;} |
        Select-Object -Property timecreated, @{label='username';expression={$_.properties[1].value}} | Select-Object -First 1
        
        $Owner = $events.username

        }
    }


$DisconnectedSessions = Get-Sessions | ? {$_.UserName -ne "" -And $_.Username -like "$Owner" } | Select ID, UserName


        if ($Owner -eq "Administrator") {
            LogWrite "Cannot kick out the administrator"
        }
        else {

        LogWrite "Blocking SMB Acces for User $Owner"

        Get-SmbShare | Block-SmbShareAccess –AccountName $Owner -Name $FileShareName -Force >> $LogPath
    
             try {
             
             Close-SmbSession -Force -ClientUserName "DOMAIN\$Owner" -ErrorAction Stop >> $LogPath

             LogWrite "Disconnected SMB sessions for User $Owner" 
             }
             catch [Exception] {

                  if ($_.Exception -match "No MSFT_SMBSession objects found with property 'ClientUserName' equal to ") {
                  LogWrite "No SMBSessions found for user $Owner"
            
                  }
   
            }

        LogWrite  "===================="
        LogWrite  "Disconnected Users"
        LogWrite  "-----------------------"

            foreach ($session in $DisconnectedSessions )
            {

                logoff $session.ID
                LogWrite $session.Username 
                LogWrite "===================="
               
  
            }
        DisplaySummary
        Sendmail
        }

}
else {
LogWrite "Disconnecting the user is Disabled"
}
break
} 
function Sendmail {

    $from = "FROMADDRESS@Email.com"
    $To = "TOADDRESS@Email.com"
    $Logfile = "PATHTOLOGFILE\SentMail.log"
    $smtpServer = "SMTPSERVER"
    $Subject = "Crypted File Found! - User $Owner Disabled"
    $Body = (Get-Content $LogFile | out-string) -join '<BR>'

     #Building a new msg object
     $msg = new-object Net.Mail.MailMessage

     #Building new smtp server object
     $smtp = new-object Net.Mail.SmtpClient($smtpServer)


     $msg.From = $from
     $msg.To.Add($To)
     $msg.subject = $Subject
     $msg.body = $Body

     #Sending E-mail
     $smtp.Send($msg)
   
}
function DisplaySummary {


$TotalFiles = $CleanCount + $CryptCount

$stopwatch.Stop()
$Stopwatchtime = [math]::Truncate([double]$stopwatch.Elapsed.TotalSeconds * 100) / 100


LogWrite "                                                      "
LogWrite "===================================================== " 
LogWrite "Summary:"
LogWrite "===================================================== " 
LogWrite "Total Files: $TotalFiles"
LogWrite "Clean Files: $CleanCount"
LogWrite "Encrypted Files: $CryptCount"
LogWrite "Excluded Files: $ExcludedFileCount"
LogWrite "===================================================== "
LogWrite "===================================================== "
LogWrite "Overall Statistics:"
LogWrite "===================================================== "
LogWrite "Entropy Hits: $SuspiciousEntropy"
LogWrite "Mean Hits: $SuspiciousMean"
LogWrite "Monte Hits: $SuspiciousMonte"
LogWrite "Chi Hits: $SuspiciousChi"
LogWrite "Serial Hits: $SuspiciousSerial"
LogWrite "===================================================== " 
LogWrite "Running of the script took: $Stopwatchtime seconds"

}
