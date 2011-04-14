@ECHO OFF
REM Die Kodierung der Eingabeaufforderung k�nnen Sie mit CHCP cp1252 �ndern.

SET JCRYPT=..\jcrypt\jcrypt.jar
SET CHIFFRE_DIR=..\00_caesar

SET JOB=task0.Caesar
SET ACTION=makekey
SET KEY=%CHIFFRE_DIR%\key.txt

java ^
-classpath %JCRYPT%;%CHIFFRE_DIR%\bin ^
de.tubs.cs.iti.jcrypt.chiffre.Launcher ^
-execute %JOB% ^
-action %ACTION% ^
-key %KEY%