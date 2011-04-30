/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        RunningKey.java
 * Beschreibung: Dummy-Implementierung der Chiffre mit laufendem Schlüssel
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

/**
 * Dummy-Klasse für die Chiffre mit laufendem Schlüssel.
 *
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 16:23:47 CEST 2010
 */
public class RunningKey extends Cipher {
	
	final boolean DEBUG = true;

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

  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {
	//if(DEBUG) testMethod();

	if(DEBUG) System.out.println(">>>makeKey called");
    int alphabetLength = 0; //Laenge des verwendeten Alphabets
    String keypath = null; //Datei mit Schluesseltext
    
    BufferedReader standardInput = launcher.openStandardInput();
    
    //Einlesen der Größe des Alphabets
    boolean accepted = false;
    String msg = "Bitte geben Sie die Größe des verwendeten Alphabetes ein:";
    System.out.println(msg);
    do {
      System.out.print("Geben Sie die Größe des Alphabetes ein: ");
      try {
        alphabetLength = Integer.parseInt(standardInput.readLine());
        if (alphabetLength < 1) {
          System.out.println(
        		  "Eine Größe des Alphabetes unter 1 wird nicht akzeptiert. " +
        		  "Bitte korrigieren Sie Ihre Eingabe.");
        } else {
	        msg = "Die Größe des Alphabetes wurde aktzeptiert. Das Alphabet umfasst " +
	        	alphabetLength + " Zeichen.";
	        System.out.println(msg);
	        accepted = true;
          
        }
      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen der Alphabetsgröße. Bitte korrigieren"
            + " Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err
            .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    
    //Einlesen des Dateinamens für Schlüsseltext
    accepted = false;
    do {
      try {
        System.out.print("Geben Sie den Dateinamen des Schlüsseltextes ein: ");
        keypath = standardInput.readLine();
        if (keypath.length() > 0) {
          msg = "Der Pfad zur Schlüsseldatei lautet: " + keypath;
          System.out.println(msg);
          accepted = true;
        } else {
          System.out.println("Der Dateiname ist zu kurz. " +
          		"Es ist mindestens ein Zeichen erforderlich.");
        }
      } catch (IOException e) {
        System.err
            .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    
    //Erzeuge key
    if(accepted) {
    	String keySafed = "" + alphabetLength + " " + keypath;
	    try {
			BufferedWriter bw = new BufferedWriter(new FileWriter("key.txt"));
			bw.write("" + alphabetLength);
			bw.write(" ");
			bw.write(keypath);
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}   
    } 
    
//    //Setze globalen Moduls (Alphabetlänge)
//    modulus = alphabetLength;
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

  }
  
  private void testMethod() {
	  System.out.println(">>>testMethod called");
	
	  
	  
	  System.out.println(">>>/testMethod finished");
	  System.exit(0);
  }
}
