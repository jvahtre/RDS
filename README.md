# RDS


# RDS
A Powershell script, consisting of 3 scripts which are used to identify encrypted files in a predetermined folder by analyzing the files with different statistical data analysis algorithms. 

If an encrypted file is found, the offending user is determined, the SMB Access for the share is blocked and the administrator is e-mailed. 

The main script provides the possibilities to choose which statistical data analysis algorithm to use, whether to enable the disconnecting of the user, set Excluded Files and provide the threshold values for each of the statistical data analysis algorithm. 
Furthermore, the main script includes the locations of the log files and the possibility to choose how long the script will be looking for encrypted files. 

In order to implement the script, the ENT program by John Walker (http://www.fourmilab.ch/random/) needs to be downloaded, the variables need to be set and also the configuration on the server side of enabling access auditing need to be implemented on the share/folder under observation.


Sample view of detection: 

![tracks](https://github.com/jvahtre/RDS/blob/master/Sample.png)

