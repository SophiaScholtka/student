@ECHO OFF
REM Die Kodierung der Eingabeaufforderung k�nnen Sie mit CHCP cp1252 �ndern.

java ^
-classpath ..\jcrypt\jcrypt.jar ^
de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables ^
..\alphabet\prozess.alph ^
..\text\prozess.txt ^
4 ^
100