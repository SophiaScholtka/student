@ECHO OFF
REM Die Kodierung der Eingabeaufforderung können Sie mit CHCP cp1252 ändern.

SET JCRYPT=..\jcrypt\jcrypt.jar
SET CHIFFRE_DIR=..\00_caesar
SET TEXT_DIR=..\text

SET JOB=task0.Caesar
SET ACTION=encipher
SET KEY=%CHIFFRE_DIR%\key33.txt
SET CLEARTEXT=%TEXT_DIR%\programmierer.txt
SET CIPHERTEXT=%CHIFFRE_DIR%\programmierer_enc.txt

java ^
-classpath %JCRYPT%;%CHIFFRE_DIR%\bin ^
de.tubs.cs.iti.jcrypt.chiffre.Launcher ^
-execute %JOB% ^
-action %ACTION% ^
-key %KEY% ^
-cleartext %CLEARTEXT% ^
-ciphertext %CIPHERTEXT%