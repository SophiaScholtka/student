/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Caesar.java
 * Beschreibung: Implementierung der Caesar-Chiffre
 * Erstellt:     09. September 2000
 * Autoren:      Martin Klußmann, Markus Seemann
 */

package task0;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.StringTokenizer;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;

/**
 * Diese Klasse implementiert die Caesar-Chiffre.
 * 
 * @author Martin Klußmann, Markus Seemann
 * @version 2.0 - Sun Mar 28 15:41:11 CEST 2010
 * @see <a href="http://de.wikipedia.org/wiki/Verschiebechiffre">Caesar-Chiffre
 * bei Wikipedia</a>
 */
public final class Caesar extends Cipher {

  /**
   * Gibt an, um wie viele Zeichen zyklisch verschoben werden soll.
   */
  private int shift;

  /**
   * Analysiert den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext, bricht die Chiffre und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   * <p>Das in der Analyse bestimmte häufigste Zeichen des Chiffretextes wird
   * verglichen mit dem vorherrschenden Zeichen einer geeigneten
   * Häufigkeitstabelle für Unigramme. Abhängig davon, ob ein Modulus angegeben
   * oder ein benutzerdefiniertes Alphabet verwendet wurde (letzteres impliziert
   * einen Modulus), wird eine andere Tabelle zum Vergleich herangezogen. Der
   * Abstand dieser beiden häufigsten Zeichen liefert den gesuchten
   * <code>shift</code>.</p>
   *  
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

    try {

      // Einlesen der Daten der Häufigkeitstabelle. Je nachdem, ob der benutzte
      // Zeichensatz durch Angabe eines Modulus oder durch Angabe eines
      // Alphabets definiert wurde, wird auf unterschiedliche Tabellen
      // zugegriffen.
      // 'nGrams' nimmt die Daten der Häufigkeitstabelle auf.
      ArrayList<NGram> nGrams = FrequencyTables.getNGramsAsList(1, charMap);
      // Bestimme das häufigste Zeichen aus der zugehörigen Unigramm-Tabelle.
      System.out.println("Häufigstes Zeichen in der Unigramm-Tabelle: "
          + nGrams.get(0).getCharacters());
      // Bestimme das häufigste Zeichen des Chiffretextes.
      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      // 'number' zählt alle Zeichen im Chiffretext.
      int number = 0;
      // 'quantities' enthält zu allen aufgetretenen Zeichen (keys der Hashmap)
      // deren zugehörige Anzahlen (values der Hashmap).
      HashMap<Integer, Integer> quantities = new HashMap<Integer, Integer>();
      // Lese zeichenweise aus der Chiffretextdatei, bis das Dateiende erreicht
      // ist.
      while ((character = ciphertext.read()) != -1) {
        number++;
        // Bilde 'character' auf dessen interne Darstellung ab.
        character = charMap.mapChar(character);
        // Erhöhe die Anzahl für dieses Zeichen bzw. lege einen neuen Eintrag
        // für dieses Zeichen an.
        if (quantities.containsKey(character)) {
          quantities.put(character, quantities.get(character) + 1);
        } else {
          quantities.put(character, 1);
        }
      }
      ciphertext.close();
      // Suche das häufigste Zeichen in 'quantities'.
      // 'currKey' ist der aktuell betrachtete Schlüssel der Hashmap (ein
      // Zeichen des Chiffretextalphabets).
      int currKey = -1;
      // Der Wert zum aktuellen Schlüssel (die Anzahl, mit der 'currKey' im
      // Chiffretext auftrat).
      int currValue = -1;
      // Die bisher größte Anzahl.
      int greatest = -1;
      // Das bisher häufigste Zeichen.
      int mostFrequented = -1;
      Iterator<Integer> it = quantities.keySet().iterator();
      while (it.hasNext()) {
        currKey = it.next();
        currValue = quantities.get(currKey);
        if (currValue > greatest) {
          greatest = currValue;
          mostFrequented = currKey;
        }
      }
      // Das häufigste Zeichen 'mostFrequented' des Chiffretextes muß vor der
      // Ausgabe noch in Dateikodierung konvertiert werden.
      System.out.println("Häufigstes Zeichen im Chiffretext: "
          + (char) charMap.remapChar(mostFrequented));

      // Berechne die im Chiffretext verwendete Verschiebung.
      int computedShift = mostFrequented
          - charMap.mapChar(Integer.parseInt(nGrams.get(0).getIntegers()));
      if (computedShift < 0) {
        computedShift += modulus;
      }
      shift = computedShift;
      System.out.println("Schlüssel ermittelt.");
      System.out.println("Modulus: " + modulus);
      System.out.println("Verschiebung: " + shift);

    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Lesen aus der "
          + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   * <p>Um eine Caesar-Chiffre zu dechiffrieren, muß jedes Zeichen aus der
   * Chiffretextdatei um <code>shift</code> Stellen im Alphabet zyklisch nach
   * links verschoben werden. Ein gelesenes Zeichen <code>char</code> wird also
   * abgebildet durch eine Funktion g mit</p>
   * <p align="center">g (<code>char</code>) = (<code>char</code> -
   * <code>shift</code>) % <code>modulus</code></p>
   * <p>Darin steht % für den Modulo-Operator.</p>
   * 
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {

    // Kommentierung analog 'encipher(cleartext, ciphertext)'.
    try {
      int character;
      while ((character = ciphertext.read()) != -1) {
        character = charMap.mapChar(character);
        if (character != -1) {
          character = (character - shift + modulus) % modulus;
          character = charMap.remapChar(character);
          cleartext.write(character);
        } else {
          // Ein überlesenes Zeichen sollte bei korrekter Chiffretext-Datei
          // eigentlich nicht auftreten können.
        }
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
          + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen
   * Klartext und schreibt den Chiffretext mit dem Writer
   * <code>ciphertext</code>.
   * <p>Zeichen aus der Klartextdatei, die im benutzten Alphabet nicht enthalten
   * sind, werden überlesen, sofern sie nicht auf den Sammelbuchstaben &middot;
   * abgebildet werden. Die Caesar-Chiffre verschiebt jeden aus der
   * Klartextdatei gelesenen Buchstaben um <code>shift</code> Stellen im
   * Alphabet zyklisch nach rechts. Ein gelesenes Zeichen <code>char</code> wird
   * also abgebildet durch eine Funktion f mit</p>
   * <p align="center">f (<code>char</code>) = (<code>char</code> +
   * <code>shift</code>) % <code>modulus</code></p>
   * <p>Darin steht % für den Modulo-Operator.</p>
   * 
   * @param cleartext
   * Der Reader, der den Klartext liefert.
   * @param ciphertext
   * Der Writer, der den Chiffretext schreiben soll.
   */
  public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {

    // An dieser Stelle könnte man alle Zeichen, die aus der Klartextdatei
    // gelesen werden, in Klein- bzw. Großbuchstaben umwandeln lassen:
    // charMap.setConvertToLowerCase();
    // charMap.setConvertToUpperCase();

    try {
      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      // 'characterSkipped' zeigt an, daß ein aus der Klartextdatei gelesenes
      // Zeichen mit dem gewählten Alphabet nicht abgebildet werden konnte.
      boolean characterSkipped = false;
      // Lese zeichenweise aus der Klartextdatei, bis das Dateiende erreicht
      // ist. Der Buchstabe a wird z.B. als ein Wert von 97 gelesen.
      while ((character = cleartext.read()) != -1) {
        // Bilde 'character' auf dessen interne Darstellung ab, d.h. auf einen
        // Wert der Menge {0, 1, ..., Modulus - 1}. Ist z.B. a der erste
        // Buchstabe des Alphabets, wird die gelesene 97 auf 0 abgebildet:
        // mapChar(97) = 0.
        character = charMap.mapChar(character);
        if (character != -1) {
          // Das gelesene Zeichen ist im benutzten Alphabet enthalten und konnte
          // abgebildet werden. Die folgende Quellcode-Zeile stellt den Kern der
          // Caesar-Chiffrierung dar: Addiere zu (der internen Darstellung von)
          // 'character' zyklisch den 'shift' hinzu.
          character = (character + shift) % modulus;
          // Das nun chiffrierte Zeichen wird von der internen Darstellung in
          // die Dateikodierung konvertiert. Ist z.B. 1 das Ergebnis der
          // Verschlüsselung (also die interne Darstellung für b), so wird dies
          // konvertiert zu 98: remapChar(1) = 98. Der Wert 98 wird schließlich
          // in die Chiffretextdatei geschrieben.
          character = charMap.remapChar(character);
          ciphertext.write(character);
        } else {
          // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
          characterSkipped = true;
        }
      }
      if (characterSkipped) {
        System.out.println("Warnung: Mindestens ein Zeichen aus der "
            + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde "
            + "überlesen.");
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
          + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * <p>Der Schlüssel einer Caesar-Chiffre besteht aus der Mächtigkeit des
   * benutzten Alphabets (<code>modulus</code>) und der Angabe, um wie viele
   * Zeichen zyklisch verschoben werden soll (<code>shift</code>).</p>
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {

    BufferedReader standardInput = launcher.openStandardInput();
    boolean accepted = false;
    String msg = "Geeignete Werte für den Modulus werden in der Klasse "
        + "'CharacterMapping'\nfestgelegt. Probieren Sie ggf. einen Modulus "
        + "von 26, 27, 30 oder 31.\nDie Verschiebung muß größer oder gleich 0 "
        + "und kleiner als der gewählte\nModulus sein.";
    System.out.println(msg);
    // Frage jeweils solange die Eingabe ab, bis diese akzeptiert werden kann.
    do {
      System.out.print("Geben Sie den Modulus ein: ");
      try {
        modulus = Integer.parseInt(standardInput.readLine());
        if (modulus < 1) {
          System.out.println("Ein Modulus < 1 wird nicht akzeptiert. Bitte "
              + "korrigieren Sie Ihre Eingabe.");
        } else {
          // Prüfe, ob zum eingegebenen Modulus ein Default-Alphabet existiert.
          String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modulus);
          if (!defaultAlphabet.equals("")) {
            msg = "Vordefiniertes Alphabet: '" + defaultAlphabet
                + "'\nDieses vordefinierte Alphabet kann durch Angabe einer "
                + "geeigneten Alphabet-Datei\nersetzt werden. Weitere "
                + "Informationen finden Sie im Javadoc der Klasse\n'Character"
                + "Mapping'.";
            System.out.println(msg);
            accepted = true;
          } else {
            msg = "Warnung: Dem eingegebenen Modulus kann kein Default-"
                + "Alphabet zugeordnet werden.\nErstellen Sie zusätzlich zu "
                + "dieser Schlüssel- eine passende Alphabet-Datei.\nWeitere "
                + "Informationen finden Sie im Javadoc der Klasse 'Character"
                + "Mapping'.";
            System.out.println(msg);
            accepted = true;
          }
        }
      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen des Modulus. Bitte korrigieren"
            + " Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err
            .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    accepted = false;
    do {
      try {
        System.out.print("Geben Sie die Verschiebung ein: ");
        shift = Integer.parseInt(standardInput.readLine());
        if (shift >= 0 && shift < modulus) {
          accepted = true;
        } else {
          System.out.println("Diese Verschiebung ist nicht geeignet. Bitte "
              + "korrigieren Sie Ihre Eingabe.");
        }
      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen der Verschiebung. Bitte "
            + "korrigieren Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err
            .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
  }

  /**
   * Liest den Schlüssel mit dem Reader <code>key</code>.
   * 
   * @param key
   * Der Reader, der aus der Schlüsseldatei liest.
   * @see #makeKey makeKey
   * @see #writeKey writeKey
   */
  public void readKey(BufferedReader key) {

    try {
      StringTokenizer st = new StringTokenizer(key.readLine(), " ");
      modulus = Integer.parseInt(st.nextToken());
      System.out.println("Modulus: " + modulus);
      shift = Integer.parseInt(st.nextToken());
      System.out.println("Verschiebung: " + shift);
      key.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Lesen oder Schließen der "
          + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    } catch (NumberFormatException e) {
      System.err.println("Abbruch: Fehler beim Parsen eines Wertes aus der "
          + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Schreibt den Schlüssel mit dem Writer <code>key</code>.
   * <p>Der Modulus und die Verschiebung werden durch ein Leerzeichen getrennt
   * in die Schlüsseldatei geschrieben. Eine solche Schlüsseldatei hat also das
   * folgende Format:
   * <pre style="background-color:#f0f0f0; border:1pt silver solid;
   * padding:3px">
   * modulus shift</pre></p>
   * 
   * @param key
   * Der Writer, der in die Schlüsseldatei schreibt.
   * @see #makeKey makeKey
   * @see #readKey readKey
   */
  public void writeKey(BufferedWriter key) {

    try {
      key.write(modulus + " " + shift);
      key.newLine();
      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der "
          + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }
}
