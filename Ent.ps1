<#
.SYNOPSIS
   Analysis script to determine whether a file is encrypted or not. 

.NOTES
   File Name: Ent.ps1
   Author   : Jaan Vahtre
   Version  : 1.0

#>


function FindEncrypted {

#Start program stopwatch
$stopwatch = [diagnostics.stopwatch]::StartNew()

#Variables

#Path Variables
$DataPath = $Path + $Data
$CryptPath = $Path + $Crypt
$CleanPath = $Path + $Clean
$LogPath = $Path + $SMBLog

#HIT Paths
$EntropyHitPath = $Path + $EntropyData
$MeanHitPath = $Path + $MeanData
$ChiHitPath = $Path + $ChiData
$MonteHitPath = $Path + $MonteData
$SerialHitPath = $Path + $SerialData

#Clean Paths
$EntropyCleanPath = $Path + $EntropyCleanData
$MeanCleanPath = $Path + $MeanCleanData
$ChiCleanPath = $Path + $ChiCleanData
$MonteCleanPath = $Path + $MonteCleanData
$SerialCleanPath = $Path + $SerialCleanData


#Encrypted Serial can also be negative
$MinusEncryptedSerial = -$EncryptedSerial

#Set up the counters
$SuspiciousEntropy = 0
$SuspiciousChi = 0
$SuspiciousMean = 0
$SuspiciousMonte = 0
$SuspiciousSerial = 0

$EncryptedFile = 0
$CleanCount = 0
$CryptCount = 0
$EntropyHit = 0
$ChiHit = 0
$SerialHit = 0
$MeanHit = 0

$Hit=0 
$HitValue = 0


#Setup start time and date.
$StartTime = (Get-Date)

#Add File Name to Both the Clean file list and cryped file list
echo "Filename" > $CryptPath
echo "Filename" > $CleanPath
echo "Filename" > $EntropyHitPath
echo "Filename" > $MeanHitPath
echo "Filename" > $ChiHitPath
echo "Filename" > $SerialHitPath
echo "Filename" > $MonteHitPath
echo "Filename" > $EntropyCleanPath
echo "Filename" > $MeanCleanPath
echo "Filename" > $ChiCleanPath
echo "Filename" > $SerialCleanPath
echo "Filename" > $MonteCleanPath

#Clean Log File.
echo " " > $LogFile

    #Start Scanning Recursively
    Get-ChildItem $SearchDirectory -Recurse -Exclude $ExcludedFiles |  % {

    #Set FileName For each file

    $FilePath = $_.FullName
    $File = $_.Name


   #Execution of Random Calculator Program
    $Command = C:\'Powershell skriptid'\ENT\ent.exe -t $FilePath > $DataPath

        #Import the results and display them as individual objects
        Import-Csv $DataPath | foreach {

            $Object = new-object PSObject -property @{


            Filebytes = $_."File-bytes"

            Entroopia = $_.Entropy

            Chi = $_."Chi-square"

            Mean = $_.Mean

            Monte = $_."Monte-Carlo-Pi"

            Serial = $_."Serial-Correlation"

            } | Select Filebytes, Entroopia, Chi, Serial, Mean, Monte



        #Trim  Mean,Monte and chi-square values 
        $Mean = [math]::Truncate([double]$_.Mean * 10) / 10
        $Monte = [math]::Truncate([double]$_."Monte-Carlo-Pi" * 100) / 100
        $Chi = [math]::Truncate([double]$_."Chi-square" * 10) / 10
        $Entropy = [math]::Truncate([double]$_."Entropy" * 1000000) / 1000000


         #Check Entropy. If it's greater than 7.99984 setup the file as suspicious and add 1 to EncryptedFile flag.
            if ($EvaluateEntropy) {

            $HitValue++

                if ($Entropy -ge $EncryptedEntropy) {

                Write-Output $File >> $EntropyHitPath


                $EncryptedFile++
                $SuspiciousEntropy++
                $EntropyHit = 1
                $Hit++

                }
                else {

                Write-Output $File >> $EntropyCleanPath

                $EntropyHit = 0

                }
            }

         #Serial Testing
            if ($EvaluateSerial) {

            $HitValue++

                if ($_."Serial-Correlation" -ge "$MinusEncryptedSerial" -Or $_."Serial-Correlation" -ge "$EncryptedSerial") { 

                #Clean File

                Write-Output $File >> $SerialCleanPath


                $SerialHit = 0
                }
                else {

                Write-Output $File >> $SerialHitPath

                $EncryptedFile++
                $SuspiciousSerial++
                $SerialHit = 1
                $Hit++
                }
            }

            #Mean Testing
            if ($EvaluateMean) {

            $HitValue++

                if ($Mean -ge $LowestEncryptedMean -And $Mean -le $HighestEncryptedMean -or $Mean -eq $EncryptedMean ) {

                Write-Output $File >> $MeanHitPath

                $EncryptedFile++
                $SuspiciousMean++
                $MeanHit = 1
                $Hit++

                }
                else {

                Write-Output $File >> $MeanCleanPath

                $MeanHit = 0
                }
            }

            #Monte Testing
            if ($EvaluateMonte) {

            $HitValue++

                if ($Monte -eq $EncryptedMonte -or $Monte -ge $LowestEncryptedMonte -And $Monte -le $HighestEncryptedMonte ) {

                Write-Output $File >> $MonteHitPath

                $EncryptedFile++
                $SuspiciousMonte++
                $MonteHit = 1
                $Hit++
                }
                else {

                Write-Output $File >> $MonteCleanPath

                $MonteHit = 0
                }
            }

            #Chi-square Testing
            if ($EvaluateChi) {

            $HitValue++

                if ($Chi -ge $EncryptedChi) {

                #The file is not encrypted
                $ChiHit = 0

                Write-Output "$File" >> $ChiCleanPath
                }
                #Otherwise it's encrypted
                else {

                Write-Output "$File" >> $ChiHitPath


                $EncryptedFile++
                $SuspiciousChi++
                $ChiHit = 1
                $Hit++

                }
            }

            if ($Hit -ge $HitValue) {

            $CryptCount++

            EncryptedFileFound
            DisableUser

            $ChiHit = 0
            $MonteHit = 0
            $SerialHit = 0
            $EntropyHit = 0
            $MeanHit = 0

            $EncryptedFile = 0
            $Hit = 0
            $HitValue = 0

            }

            else {

            #Pure File - Send the data to CleanPath File.
            Write-Output "Clean File" >> $CleanPath
            Write-Output "$File" >> $CleanPath
            Write-Output $Object >> $CleanPath
            Write-Output "==================================================== " >> $CleanPath
            $CleanCount++
            $EncryptedFile = 0
            $Hit= 0
            $HitValue = 0

            }
        }
    }

$TotalFiles = $CleanCount + $CryptCount


#Set the ending time and the total time it took to run the test.

$EndTime = (Get-Date)
$RunTime = New-TimeSpan -Start $StartTime -End $EndTime
Write-Output "The Running of the Script ended at: $EndTime" >> $CleanPath
Write-Output "The Running of the Script ended at: $EndTime" >> $CryptPath


#Stop the stopwatch.

$stopwatch.Stop()
$Stopwatchtime = [math]::Truncate([double]$stopwatch.Elapsed.TotalSeconds * 100) / 100

Write-Output "Total time was $Stopwatchtime seconds" >> $CryptPath
Write-Output "Total time was $Stopwatchtime seconds" >> $CleanPath
Write-Output "===================================================== " >> $CryptPath
Write-Output "===================================================== " >> $CleanPath

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



