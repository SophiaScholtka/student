/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Vigenere.java
 * Beschreibung: Dummy-Implementierung der Vigenère-Chiffre
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task1;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Arrays;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

//import java.util.StringTokenizer;

/**
 * Dummy-Klasse für die Vigenère-Chiffre.
 *
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 15:53:38 CEST 2010
 */
public class Vigenere extends Cipher {
	private int[] shifts;
	private int keylength;

  /**
   * Analysiert den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext, bricht die Chiffre bzw. unterstützt das Brechen der Chiffre
   * (ggf. interaktiv) und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   *
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  /**
   * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   *
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
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
      int counter=1;
      while ((character = ciphertext.read()) != -1) {
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
          character = (character - shifts[counter]+modulus) % modulus;
          // Das nun chiffrierte Zeichen wird von der internen Darstellung in
          // die Dateikodierung konvertiert. Ist z.B. 1 das Ergebnis der
          // Verschlüsselung (also die interne Darstellung für b), so wird dies
          // konvertiert zu 98: remapChar(1) = 98. Der Wert 98 wird schließlich
          // in die Chiffretextdatei geschrieben.
          character = charMap.remapChar(character);
          cleartext.write(character);
        } else {
          // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
          characterSkipped = true;
        }
        counter=(counter+1)%(keylength+1);
        if(counter==0) counter=1;
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
   * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen
   * Klartext und schreibt den Chiffretext mit dem Writer
   * <code>ciphertext</code>.
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
      int counter=1;
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
          character = (character + shifts[counter]) % modulus;
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
        counter=(counter+1)%(keylength+1);
        if(counter==0) counter=1;
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
	        msg = "Bitte geben Sie die Länge des Schlüssels ein:";
	        System.out.println(msg);
	        keylength = Integer.parseInt(standardInput.readLine());
	        }
	      } catch (NumberFormatException e) {
	        System.out.println("Fehler beim Parsen des Modulus oder der Schlüssellänge. Bitte korrigieren"
	            + " Sie Ihre Eingabe.");
	      } catch (IOException e) {
	        System.err
	            .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
	        e.printStackTrace();
	        System.exit(1);
	      }
	    } while (!accepted);
	    accepted = false;
	    shifts = new int[keylength+1];
	    shifts[0]=modulus;
	    do {
	      try {
	        System.out.print("Geben Sie den Schlüssel ein: ");
	        char[] passW = standardInput.readLine().toCharArray();
	        for(int i = 1; i<=keylength; i++){
	        	shifts[i]=passW[i-1]-'a';
	        	if (shifts[i] >= 0 && shifts[i] < modulus) {
	        		accepted = true;
	        	} else {
		          System.out.println("Diese Verschiebung ist nicht geeignet. Bitte "
		              + "korrigieren Sie Ihre Eingabe.");
		          accepted = false;
		          break;
		        }
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
      modulus = Integer.parseInt(key.readLine());
      System.out.println("Modulus: " + modulus);
      keylength = Integer.parseInt(key.readLine());
      System.out.println("Schlüssellänge: " + keylength);
      shifts = new int[keylength+1];
      shifts[0]=modulus;
      for(int i=1;i<=keylength;i++){
    	  shifts[i]=Integer.parseInt(key.readLine());
      }
      System.out.println("Modulus+Schlüssel: " + Arrays.toString(shifts));
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
   * 
   * @param key
   * Der Writer, der in die Schlüsseldatei schreibt.
   * @see #makeKey makeKey
   * @see #readKey readKey
   */
  public void writeKey(BufferedWriter key) {

    try {
      key.write(""+modulus);
      key.newLine();
      key.write(""+keylength);
      for(int i=1;i<=keylength;i++){
    	  key.newLine();
    	  key.write(""+shifts[i]);
      }
      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der "
          + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }
}