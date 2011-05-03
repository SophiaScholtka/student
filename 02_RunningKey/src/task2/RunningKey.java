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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.lang.Math;

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
	//Bereite Schlüsseltext-Datei vor
	keyFilePath = "key_text.txt"; //Datei mit Schlüsseltext
	writeToFile(keyFilePath, ""); //Legt die Datei für Schlüsseltext an
	
	
	//Erfrage vermutete Alphabetgröße/Modulus
	BufferedReader standardInput = launcher.openStandardInput();
	boolean accepted = false;

	String msg = "Bitte geben Sie die Größe des vermuteten Alphabetes ein:";
	System.out.println(msg);
	do {
	  msg = "Bitte geben Sie die Größe des vermuteten Alphabetes ein:";
	  try {
		modulus = Integer.parseInt(standardInput.readLine());
		if (modulus < 1) {
		  System.out.println(
				  "Eine Größe des Alphabetes unter 1 wird nicht akzeptiert. " +
				  "Bitte korrigieren Sie Ihre Eingabe.");
		} else {
			msg = "Die Größe des Alphabetes wurde aktzeptiert. Das verwendete Alphabet umfasst " +
				modulus + " Zeichen.";
			System.out.println(msg);
			accepted = true;  
		}
	  } catch (NumberFormatException e) {
		  System.out.println("Fehler beim Parsen der Alphabetsgröße. Bitte korrigieren"
				 + " Sie Ihre Eingabe.");
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
	} while (!accepted);
	
	
	//Chiffre start
	msg = "Beginne mit dem Verfahren zum Brechen der Chiffre.";
	System.out.println(msg);
	  
	//Lese die Buchstaben des Ciphertextes ein
	  ArrayList<Integer> cipherChars;
	  cipherChars = readBufferedReaderToList(ciphertext);
	
	  //Mache Platz für Klartext und Schlüsseltext
	  int[] klartext=new int[cipherChars.size()];
	  int[] schluesseltext=new int[cipherChars.size()];
	  
	//Fülle Klar-und Schlüsseltext mit -1 damit festgestellt werden kann, ob eine Textstelle schon behandelt wurde
	  for(int i=0;i<klartext.length;i++) klartext[i]=-1;
	  for(int i=0;i<schluesseltext.length;i++) schluesseltext[i]=-1;
	   
	//Solange der User noch Lust hat, Textteile zu entziffern: 
	boolean fertig=false;
	do {
		//Erfrage die Position und Länge des Ciphertextabschnittes, den der User betrachten möchte
		int start=0; int laenge=4;
		//TODO 0 und 4 durch User-Eingaben Start und Länge ersetzen
		ArrayList<Integer> abschnitt = getAbschnitt(start,laenge,cipherChars);
		//Zeige bereits entschlüsselte Abschnitte, falls sie angrenzen/überlappen
		showClearAndKeyText(start,laenge,klartext,schluesseltext);
		//Analysiere den Abschnitt auf wahrscheinliche Klar & Schlüsseltexte
		//Bitte den User um eine Auswahl und speichere sein Ergebnis ab
		//Abfrage ob der Text vollständig bearbeitet wurde oder der User schon zufrieden ist, dann
		fertig=true;
	} while (!fertig);
  }

private void showClearAndKeyText(int start, int laenge, int[] klartext, int[] schluesseltext) {
	if(start < 0) start = 0;
	if(laenge < 0) laenge = 0;
	//TODO, prüfe ob es angrenzend oder überlappend zum Textabschnitt ab start 
	//bis start+laenge bereits entschlüsselte Textstellen gibt.
	boolean notext=true;
	for(int i=Math.max(start-1,0);i<Math.min(start+laenge+1,klartext.length);i++){
		if(klartext[i]!=-1 && schluesseltext[i]!=-1) notext=false;
	}
	if(notext) {
		System.out.println("Kein bereits entschlüsselter Abschnitt grenzt an den gewählten Abschnitt");
	} else {
		int j=Math.max(start-1,0);
		while (j>1 && klartext[j]!=-1 && schluesseltext[j]!=-1){
			j--;
		}
		int i=j;
		ArrayList<Character> klar=new ArrayList<Character>();
		ArrayList<Character> schl=new ArrayList<Character>();
		while(i<klartext.length){
			while(klartext[i]!=-1 && schluesseltext[i]!=-1){
				klar.add((char)klartext[i]);
				schl.add((char)schluesseltext[i]);
				i++;
				if(i>klartext.length) break;
			}
			System.out.println("Bereits entzifferter Klartext\n von Position "+j+" bis Position "+i+":\n"+String.valueOf(klar));
			System.out.println("Bereits entzifferter Schlüsseltext\n von Position "+j+" bis Position "+i+":\n"+String.valueOf(schl));
			j=i;
			if(j>Math.min(start+laenge+1,klartext.length)) break;
		}
	}
}

private ArrayList<Integer> getAbschnitt(int start, int laenge, ArrayList<Integer> cipherChars) {
	if(DEBUG) System.out.println(">>>getAbschnitt called");
	//Checken ob Start und Länge zulässig sind
	if (start<0 || laenge<=0 || start+laenge>=cipherChars.size()){
		System.out.println("Ungültige Eingabe. Start muss zwischen 0 und "+cipherChars.size()+" sein. \n Länge >=1 und Start+Länge <="+cipherChars.size());
		return null;
	}
	//abschnitt aus dem ciphertext herauskopieren
	ArrayList<Integer> abschnitt = new ArrayList<Integer>();
	for(int i=start;i<(start+laenge);i++){
		abschnitt.add(cipherChars.get(i));
	}
	if(DEBUG) System.out.println(">>>> Abschnitt Array: " + abschnitt.toString());
	return abschnitt;
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
	  String msg = "";
	  
	  //Lese die Buchstaben des Keys ein
	  ArrayList<Integer> keyChars,cipherChars;
	  //TODO keyFilePath ist an dieser Stelle noch null! 
	  if(keyFilePath == null) {
		  keyFilePath = "out/out.txt"; //Workaround
	  }
	  System.out.println(">>>> keyFilePath=" + keyFilePath);
	  keyChars = readFileToList(keyFilePath);
	  cipherChars = readBufferedReaderToList(ciphertext);
	  
	  if(keyChars.size() >= cipherChars.size()) {
		  doDencipher(keyChars,cipherChars,cleartext);
	  } else {
		  msg = "Schlüsseldatei ist zu klein! Verschlüsseln wird abgebrochen. " +
		  		"Empfohlene Mindestlänge des Schlüssels ist " + cipherChars.size();
		  System.out.println(msg);
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
	  if(DEBUG) System.out.println(">>>encipher called");
	  String msg = "";
	  
	  //Lese die Buchstaben des Keys ein
	  ArrayList<Integer> keyChars,clearChars;
	  keyChars = readFileToList(keyFilePath);
	  clearChars = readBufferedReaderToList(cleartext);
	  
	  if(keyChars.size() >= clearChars.size()) {
		  doEncipher(keyChars,clearChars,ciphertext);
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
		//Setze globale Variablen des Schlüssels
		modulus = alphabetLength;
		keyFilePath = keypath;
		
		//Speicherung erfolgt automatisch durch Job
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

//	//Tests für replacePartOfArrayList(...)
//	  ArrayList<Integer> ll;
//	  ArrayList<Integer> l1,l2;
//	  l1 = new ArrayList<Integer>();
//	  l2 = new ArrayList<Integer>();
//	  for(int i = 0; i < 10; i++) {
//		  l1.add(i);
//	  }
//	  for(int i = 3; i < 6; i++) {
//		  l2.add(i+100);
//	  }
//	  System.out.println("Die Listen:");
//	  System.out.println(l1.toString());
//	  System.out.println(l2.toString());
//	  System.out.println();
//	  System.out.println("Listen mit ersetztem Inhalt: (0<atStart<list.length)");
//	  ll = replacePartOfArrayList(l1, l2, 3);
//	  System.out.println(ll.toString());
//	  System.out.println("Listen mit ersetztem Inhalt: (list.length<atStart)");
//	  ll = replacePartOfArrayList(l2, l1, 1);
//	  System.out.println(ll.toString());
		  
//	  //Tests für intersectLists(...)
//	  ArrayList<ArrayList<Integer>> ll;
//	  ArrayList<Integer> l1,l2;
//	  l1 = new ArrayList<Integer>();
//	  l2 = new ArrayList<Integer>();
//	  int l = 10;
//	  for(int i = 0; i < l; i++) {
//		  l1.add(i);
//		  l2.add(i+100);
//	  }
//	  l1.add(l+1);
//	  System.out.println("Die Listen:");
//	  System.out.println(l1.toString());
//	  System.out.println(l2.toString());
//	  System.out.println();
//	  System.out.println("Listen mit getauschtem Inhalt: (0<from<to<Längen)");
//	  ll = translocateLists(l1, l2, 4, 6);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
//	  System.out.println("Listen mit getauschtem Inhalt: (from < 0)");
//	  ll = translocateLists(l1, l2, -4, 6);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
//	  System.out.println("Listen mit getauschtem Inhalt: (to < 0)");
//	  ll = translocateLists(l1, l2, 4, -6);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
//	  System.out.println("Listen mit getauschtem Inhalt: (ListSize1 < to)");
//	  ll = translocateLists(l1, l2, 4, l1.size() + 4);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
//	  System.out.println("Listen mit getauschtem Inhalt: (ListSize2 < to)");
//	  ll = translocateLists(l1, l2, 4, l2.size() + 4);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
//	  System.out.println("Listen mit getauschtem Inhalt: (from > to)");
//	  ll = translocateLists(l1, l2, 6, 4);
//	  System.out.println(ll.get(0).toString());
//	  System.out.println(ll.get(1).toString());
	  	  
	  System.out.println(">>>/testMethod finished");
	  System.exit(0);
  }
  /**
   * Liest aus einer Datei die einzelnen Zeichen aus und gibt die Zeichen als Liste zurück.
   * @param filePath	Pfad zur auszulesenden Datei
   * @return Liste der einzelnen Zeichen, Zahlenwerte der Zeichen
   */
  private ArrayList<Integer> readFileToList(String filePath) {
	  //if(DEBUG) System.out.println(">>>readfileToList called");
	  //if(DEBUG) System.out.println(">>>> filePath=" + filePath);
	  ArrayList<Integer> back = new ArrayList<Integer>();
  
	  try {
		  BufferedReader br = new BufferedReader(new FileReader(filePath));
		  back = readBufferedReaderToList(br);
	  } catch (FileNotFoundException e) {
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
	private void doEncipher(ArrayList<Integer> keyChars, 
			ArrayList<Integer> clearChars,BufferedWriter ciphertext) {
		if(DEBUG) System.out.println(">>>doEncipher called");

	// charMap.setConvertToLowerCase();
	// charMap.setConvertToUpperCase();

		try {
	  int character;
	  boolean characterSkipped = false;
	  boolean useNextKey = true;
	  	  
	  Iterator<Integer> keyIterator = keyChars.iterator();
	  Iterator<Integer> clearIterator = clearChars.iterator();
	  int shift = 0;
	  int keyChar = 0;
	  while(clearIterator.hasNext() && keyIterator.hasNext()) {
		  if(useNextKey) {
			  keyChar = keyIterator.next();	  
		  }		  
		  useNextKey = true;
		  
		  shift = keyChar;
		  character = clearIterator.next();
		  
		  if (charMap.mapChar(character) !=-1) {
			  character = charMap.mapChar(character);
			  shift = charMap.mapChar(shift);	
			  
		  character = (character + shift + modulus) % modulus;
		  character = charMap.remapChar(character);
		  ciphertext.write(character);
		  } else {
			  characterSkipped = true;
			  useNextKey = false;
	  }
	  }
	  if (characterSkipped) {
	System.out.println("Warnung: Mindestens ein Zeichen aus der "
	+ "Klartextdatei ist im Alphabet nicht\nenthalten und wurde "
	+ "überlesen.");
	  }
	} catch (IOException e) {
	  System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
	  + "Chiffretextdatei.");
	  e.printStackTrace();
	  System.exit(1);
	}
		
	}

	private void doDencipher(ArrayList<Integer> keyChars, 
			ArrayList<Integer> cipherChars, BufferedWriter cleartext) {

		  try {
		  int character;
		  int shift = 0;
		  boolean characterSkipped = false;

		  Iterator<Integer> keyIterator = keyChars.iterator();
		  Iterator<Integer> cipherIterator = cipherChars.iterator();
		  
		  ArrayList<String> newCleartext = new ArrayList<String>();
		  while(cipherIterator.hasNext() && keyIterator.hasNext()) {
			  shift     = keyIterator.next();
			  character = cipherIterator.next();
			  
			  if (charMap.mapChar(character) !=-1) {
				  character = charMap.mapChar(character);
				  shift = charMap.mapChar(shift);
	
			  character = (character - shift + modulus) % modulus;
			  character = charMap.remapChar(character);
			  newCleartext.add(Character.toString((char) character));
			  cleartext.write((char) character);
			  } else {
				  characterSkipped = true;
			  }
		  }

		  //Zeige deciphered Klartext
		  System.out.println("Ausschnitt aus dem Klartext: ");
		  Iterator<String> newClearIterator = newCleartext.iterator();
		  for (int i=0; i<100;i++) {
				System.out.print(newClearIterator.next());
			  }
		  System.out.println();
		  
		  if (characterSkipped) {
		System.out.println("Warnung: Mindestens ein Zeichen aus der "
		+ "Klartextdatei ist im Alphabet nicht\nenthalten und wurde "
		+ "überlesen.");
		  }
		
		  //erst schließen, wenn kein weiterer Zugriff erforderlich ist!
		  cleartext.close();
		  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
		  + "Chiffretextdatei.");
		  e.printStackTrace();
		  System.exit(1);
		  }
				
	}
	
	/**
	 * Tauscht ein inneres Teilstueck zweier Listen untereinander aus.
	 * - Erwartet zwei Listen
	 * - Vertauscht inneres Teilstueck (from...to, alle inklusive)
	 * - getauschte Listen werden in gleicher Reihenfolge wie bei Eingabe 
	 * zurückgegeben.
	 * Methode sorgt dafür dass 0 <= from <= to <= kleinste Listengröße.
	 * Indexe beginnen bei 0.
	 * @param list1	Liste 1
	 * @param list2	Liste 2
	 * @param from	Beginn des zu tauschenden Teilstueck-Indexes (inklusiv)
	 * @param to	Ende des zu tauschenden Teilstueck-Indexes (inklusiv)
	 * @return	die zwei neuen Listen mit vertauschtem Innerem. 
	 * Liste 1 ist die erste, Liste 2 die zweite.
	 */
	private ArrayList<ArrayList<Integer>> translocateLists(ArrayList<Integer> list1, ArrayList<Integer> list2, int from, int to)  {
		//Prüfe Listenlängen
		if(list1.size()<to+1) {
			to = list1.size() - 1;
		}
		if(list2.size()<to+1 && list2.size() < list1.size()) {
			to = list2.size() - 1;
		}
		//sorge fuer 0<=from <= to
		if(from <= 0) {
			from = 0;
		}
		if(to <= 0) {
			to = 0;
		}
		if(from > to) {
			int tmp = from;
			from = to;
			to = tmp;
		}
				
		ArrayList<ArrayList<Integer>> back;
		ArrayList<Integer> list1Back, list2Back;
		Iterator<Integer> list1Iterator,list2Iterator;
		int counter;
		
		back = new ArrayList<ArrayList<Integer>>();
		list1Back = new ArrayList<Integer>();
		list2Back = new ArrayList<Integer>();				
		list1Iterator = list1.iterator();
		list2Iterator = list2.iterator();
		
		counter = 0;
		while (list1Iterator.hasNext() && list2Iterator.hasNext()) {
			if(counter < from || to < counter) {
				list1Back.add(list1Iterator.next());
				list2Back.add(list2Iterator.next());
			} else { //if(from <= counter && counter <= to) {
				list1Back.add(list2Iterator.next());
				list2Back.add(list1Iterator.next());
			} 
			counter ++;
		}
		
		//hängt Rest der jeweiligen Listen an die Rückgabelisten an.
		while(list1Iterator.hasNext()) {
			list1Back.add(list1Iterator.next());
		}
		while(list2Iterator.hasNext()) {
			list2Back.add(list2Iterator.next());
		}
		
		//Rückgabe vorbereiten
		back.add(list1Back);
		back.add(list2Back);
		 
		return back;
	}

	/**
	 * Ersetzt einen Teil einer Liste durch neue Werte.
	 * Die neue Liste ist maximal so lang wie die alte. Alles darüber hinaus 
	 * wird ignoriert.
	 * @param list	Liste, in welcher ein Stück ersetzt werden soll
	 * @param part	zu ersetzende Werte
	 * @param atStart	Index, an welchem mit dem Ersetzen begonnen werden soll
	 * @return	Gibt die neue Liste zurück
	 */
	private ArrayList<Integer> replacePartOfArrayList(ArrayList<Integer> list, ArrayList<Integer> part, int atStart) {
		if(atStart < 0) { atStart = 0; }
		
		ArrayList<Integer> back;
		back = new ArrayList<Integer>();
		
		Iterator<Integer> listIterator = list.iterator();
		Iterator<Integer> partIterator = part.iterator();
		int value;
		int counter = 0;
		while(listIterator.hasNext() && partIterator.hasNext()) {
			if(counter < atStart) {
				value = listIterator.next();
			} else {
				listIterator.next();
				value = partIterator.next();
			}
			back.add(value);
			counter++;
		}
		
		//Fügt den bestehenden Rest der originalen Liste an
		while(listIterator.hasNext()) {
			value = listIterator.next();
			back.add(value);
		}
				
		return back;
	}
	
	  
	private void writeToFile(String filename,ArrayList<Character> text) {
		try {
			  FileWriter writer = new FileWriter(filename);
			  BufferedWriter out = new BufferedWriter(writer);
			  for(int i=0;i<text.size();i++){
				  out.append(text.get(i));
		  		}
			  out.close();
		  } catch (IOException e){
			  e.printStackTrace();
		  }
	  }
	  
	  private void writeToFile(String filename,String text) {
		  try {
			  FileWriter writer = new FileWriter(filename);
			  BufferedWriter out = new BufferedWriter(writer);
			  out.write(text);
			  out.close();
		  } catch (IOException e){
			  e.printStackTrace();
		  }
	  }
}
