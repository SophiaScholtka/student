@ECHO OFF
REM Die Kodierung der Eingabeaufforderung k�nnen Sie mit CHCP cp1252 �ndern.

java ^
-classpath ..\jcrypt\jcrypt.jar ^
de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping ^
..\alphabet\programmierer.alph