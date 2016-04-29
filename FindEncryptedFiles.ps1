<#
.SYNOPSIS
   Checks for Encrypted Files in a specified folder and logs off the offending user, when a encrypted file is found. Uses ENT.ps1 and functions.ps1. 

.DESCRIPTION
   Checks for Encrypted Files in a specified folder and logs off the offending user, when a encrypted file is found. Uses ENT.ps1 and functions.ps1.

.NOTES
   File Name: FindEncryptedFiles.ps1
   Author   : Jaan Vahtre
   Version  : 1.0

.EXAMPLE
   PS > .\FindEncryptedFiles.ps1
#>


#In order to run the script, The necessary variables need to be entered.


#Import functions script and ENT Program script.
 . "PATHTO\functions.ps1"
 . "PATHTO\ENT.ps1"

#Set the Variables

#SentMail LogFile
$Logfile = "PATHTO\SentMail.log"

#First Define the Search Directory
$SearchDirectory = "PATHTOSEARCHDIRECTORY"

#Setup the Path where ENT tool is located.
$Path = "PATHTOENTTOOLLOCATION" 

#Setup where the .csv output will be sent and read.
$Data = "Data.txt"

#Setup the path of Encrypted files log.
$Crypt = "Crypted.txt"

#Setup the path of Clean files log.
$Clean = "Clean.txt"

#Setup the path for SMB Logs.
$SMBLog = "Log.txt"

#Setup the FileNames of suspicious files log.
$EntropyData = "EntropyHit.xlsx"
$MeanData = "MeanHit.xlsx"
$ChiData = "ChiHit.xlsx"
$SerialData = "SerialHit.xlsx"
$MonteData = "MonteHit.xlsx"

#Setup the FileNames of Clean files log.
$EntropyCleanData = "CleanEntropy.xlsx"
$MeanCleanData = "CleanMean.xlsx"
$ChiCleanData = "CleanChi.xlsx"
$SerialCleanData = "CleanSerial.xlsx"
$MonteCleanData = "CleanMonte.xlsx"


#Excluded Files list. 

$ExcludedFileCount = 0
$ExcludedFiles=@("")

#Set Whether Users are disconnected or not when encryption is found.
$Disconnect = $False

#Set Whether the algorithm will be evaluated
$EvaluateEntropy = $False
$EvaluateChi = $False
$EvaluateMean = $False
$EvaluateSerial = $False
$EvaluateMonte = $False

#Set the Fileshare name, from which the User will be disconnected. If not specified, the user will be disconnected from every share. 
$FileShareName = "FILESHARENAME"


#Set the Encrypted Values for entropy, chi-square, Monte, Serial Correlation and Mean. Optimize in order to get better results, 
$EncryptedEntropy = 7.986000
$EncryptedChi = 690
$EncryptedMean = 127.5
$LowestEncryptedMean = 127.3
$HighestEncryptedMean = 127.7
$LowestEncryptedMonte = 3.12
$HighestEncryptedMonte = 3.16
$EncryptedMonte = 3.14
$EncryptedSerial = 0.001200

#Start finding the Encrypted Files. The timeout is 1440 minutes, but can be adjusted accordingly. 
#In addition, it's possible to add a task scheduler script to activate it in Every 1440 Minutes.

$timeout = new-timespan -Minutes 1440
$sw = [diagnostics.stopwatch]::StartNew()

while ($sw.elapsed -lt $timeout){
    FindEncrypted
    start-sleep -seconds 5
}
write-host "Program Closed"

