@ECHO OFF
REM Die Kodierung der Eingabeaufforderung können Sie mit CHCP cp1252 ändern.

SET JCRYPT=..\jcrypt\jcrypt.jar
SET CHIFFRE_DIR=..\00_caesar
SET ALPHABET_DIR=..\alphabet

SET JOB=task0.Caesar
SET ACTION=break
SET KEY=%CHIFFRE_DIR%\key251_break.txt
SET CLEARTEXT=%CHIFFRE_DIR%\programmierer_break.txt
SET CIPHERTEXT=%CHIFFRE_DIR%\programmierer_enc.txt
SET ALPHABET=%ALPHABET_DIR%\cp1252.alph

java ^
-classpath %JCRYPT%;%CHIFFRE_DIR%\bin ^
de.tubs.cs.iti.jcrypt.chiffre.Launcher ^
-execute %JOB% ^
-action %ACTION% ^
-key %KEY% ^
-cleartext %CLEARTEXT% ^
-ciphertext %CIPHERTEXT% ^
-alphabet %ALPHABET%