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

import java.awt.event.KeyListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

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
	
	//int keyAlphLenght; //modulus
	String keyFilePath;

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
	  if(DEBUG) System.out.println(">>>decipher called");

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
	  if(DEBUG) System.out.println(">>>encipher called");
	  String msg = "";
	  
	  //Lese die Buchstaben des Keys ein
	  ArrayList<Integer> keyChars,clearChars;
	  keyChars = readFileToList(keyFilePath);
	  clearChars = readBufferedReaderToList(cleartext);
	  
	  if(keyChars.size() >= clearChars.size()) {
		  doEncipher(keyChars,clearChars);
	  } else {
		  msg = "Schlüsseldatei ist zu klein! Verschlüsseln wird abgebrochen. " +
		  		"Empfohlene Mindestlänge des Schlüssels ist " + clearChars.size();
		  System.out.println(msg);
	  }
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
		try {
			//Setze globale Variablen des Schlüssels
			modulus = alphabetLength;
			keyFilePath = keypath;
			
			//Speichere Key
			BufferedWriter bw;
			bw = new BufferedWriter(new FileWriter("key.txt"));
			writeKey(bw);
		} catch (IOException e) {
			e.printStackTrace();
		}
    } 
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
	  if(DEBUG) System.out.println(">>>readKey called");
	  String s;
	  String[] sKey;
	  
	  try {
			s = key.readLine();
			sKey = s.split(" ", 2);
			if(DEBUG) { 
				System.out.print(">>>> Eingelesen: " + s);
				System.out.print("\t Array: " + Arrays.toString(sKey));
				System.out.println();
			}
			if(sKey.length == 2) {
				modulus = Integer.parseInt(sKey[0]);
				keyFilePath = sKey[1];
			} else {
				System.out.println("!ACHTUNG! Key wurde falsch eingelesen.");
			}
	  } catch (IOException e) {
			e.printStackTrace();
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
	  if(DEBUG) System.out.println(">>>writeKey called");
	  
	  try {
		  key.write("" + modulus);
		  key.write(" ");
		  key.write(keyFilePath);
		  //key.newLine();
		  key.close();
	  } catch (IOException e) {
		  System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der "
	          + "Schlüsseldatei.");
	      e.printStackTrace();
	      System.exit(1);
	  }
  }
  
  /**
   * Für Tests
   */
  private void testMethod() {
	  System.out.println(">>>testMethod called");
	
	  
	  
	  System.out.println(">>>/testMethod finished");
	  System.exit(0);
  }
  /**
   * Liest aus einer Datei die einzelnen Zeichen aus und gibt die Zeichen als Liste zurück.
   * @param filePath	Pfad zur auszulesenden Datei
   * @return Liste der einzelnen Zeichen, Zahlenwerte der Zeichen
   */
  private ArrayList<Integer> readFileToList(String filePath) {
	  ArrayList<Integer> back = new ArrayList<Integer>();
  
	  try {
		  BufferedReader br = new BufferedReader(new FileReader(filePath));
		  back = readBufferedReaderToList(br);
	  } catch (FileNotFoundException e) {
		  e.printStackTrace();
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  
	  return back;
  }
  
  /**
   * Liest aus einer Datei die einzelnen Zeichen aus und gibt die Zeichen als Liste zurück.
   * @param reader	BufferedReader mit der auszulesenden Datei
   * @return Liste der einzelnen Zeichen, Zahlenwerte der Zeichen
   */
  private ArrayList<Integer> readBufferedReaderToList(BufferedReader reader) {
	  ArrayList<Integer> back = new ArrayList<Integer>();
	  
	  try {
		  int character;
		  while(reader.ready()) {
			  character = reader.read();
			  back.add(character);
		  }
		  reader.close();
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  
	  return back;
  }
  	
  	/** 
  	 * Methode zur eigentlichen Verschlüsselung
  	 * @param keyChars	Liste der einzelnen Zeichen der Schlüsseldatei
  	 * @param clearChars	Liste der einzelnen Zeichen der Klartextdatei
  	 */
	private void doEncipher(ArrayList<Integer> keyChars, ArrayList<Integer> clearChars) {
		if(DEBUG) System.out.println(">>>doEncipher called");
		
	}
}
