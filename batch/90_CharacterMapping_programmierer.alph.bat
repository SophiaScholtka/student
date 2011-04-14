@ECHO OFF
REM Die Kodierung der Eingabeaufforderung können Sie mit CHCP cp1252 ändern.

java ^
-classpath ..\jcrypt\jcrypt.jar ^
de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping ^
..\alphabet\programmierer.alph