/**
 * Aufgabe 0: Beispiel-Implementierung der Caesar-Chiffre.
 * <p>Dieses vollständig ausprogrammierte Beispiel zeigt, wie jCrypt benutzt
 * werden kann und soll. Der Quelltext <a
 * href="{@docRoot}/src-html/task0/Caesar.html">Caesar.java</a> ist gut
 * kommentiert und sollte für ein grundlegendes Verständnis der
 * Programmierumgebung komplett durchgearbeitet werden. Hilfreich dabei können
 * die Eclipse-Run Configurations sein, die sich im Verzeichnis <a
 * href="{@docRoot}/../../jCrypt/launch">jCrypt/launch</a> befinden bzw. nach
 * dem Einrichten von jCrypt in Eclipse unter <code>Run &gt; Run[
 Configurations]... &gt; Java Application</code> zugänglich sind. Folgende
 * Konfigurationen sind angelegt:
 * <ul>
 * <li>00 Caesar makekey</li>
 * <li>01 Caesar encipher mod33</li>
 * <li>02 Caesar decipher mod33</li>
 * <li>03 Caesar encipher mod31</li>
 * <li>04 Caesar decipher mod31</li>
 * <li>05 Caesar break mod31</li>
 * <li>06 Caesar encipher default27_2.alph</li>
 * <li>07 Caesar decipher default27_2.alph</li>
 * <li>08 Caesar break mod27</li>
 * <li>09 Caesar encipher cp1252.alph</li>
 * <li>0A Caesar decipher cp1252.alph</li>
 * <li>0B Caesar break cp1252.alph</li>
 * <li>0C Caesar encipher utf-8-demo.alph</li>
 * <li>0D Caesar decipher utf-8-demo.alph</li>
 * </ul>
 * Bei den Konfigurationen 0C und 0D müssen die Kodierungen
 * <code>inFileEncoding</code> und <code>outFileEncoding</code> in <a
 * href="{@docRoot}/../../jCrypt/jCrypt.properties">jCrypt.properties</a>
 * (insbesondere und auch unter Microsoft Windows) auf UTF-8 eingestellt sein.
 * Beachten Sie zu jeder Konfiguration die auf der Karteikarte mit dem Reiter
 * <code>Arguments</code> angegebenen Kommandozeilenargumente.</p>
 */

package task0;