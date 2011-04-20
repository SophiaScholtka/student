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
import java.io.Console;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;

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
	  //TODOL This values need to be read in later
	  String cipher = "ciphertext-blahblubb";
	  cipher = bufferedReaderToString(ciphertext);
	  String alph = "generatedAlphabet.alph";
	  String textfile = "programmierer_enc.txt";
	  int minN = 1;
	  int maxN = 4;
	  int maxResults = 5;
	  
	  generateAlphabet(cipher,alph);
	  createFrequencyTables(alph,textfile,minN,maxN,maxResults);
	    
	  int period = calcPossiblePeriod(cipher, "trennendesNGram");
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
          character = (character - shifts[counter] + modulus) % modulus;
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
  
  private void createFrequencyTables(String alph, String textfile, int minN, int maxN, int maxResults) {
	  	//Controls the input of min and max N
	  	if(minN <= 0) { minN = 1; }
	  	if(maxN <= 0) { maxN = 1; }
	  	if(maxN < minN) { 
	  		int iTemp = minN;
	  		minN = maxN;
	  		maxN = iTemp;
	  	}
	  
		// Creates nGrams for the encrypted text
		//nGram on an special encoded text
		//String array for frequencytables.main
		String[] frequencyTablesInput = new String[4];
		frequencyTablesInput[0] = alph;
		frequencyTablesInput[1] = textfile;
		frequencyTablesInput[2] = "" + minN;
		frequencyTablesInput[3] = "" + maxResults;
		
		//Create frequency tables
		try {
			//int maxN = Integer.parseInt(frequencyTablesInput[2]);
			PrintStream ps = System.out; // for bringing back old output
			for(int i = minN;i<=maxN;i++) {
				frequencyTablesInput[2] = ""+i;
				System.setOut(new PrintStream(new FileOutputStream("generated" + i + "-grams.alph.tab")));
				//sets the default output stream to a file while the frequency table is generated
				FrequencyTables.main(frequencyTablesInput);
				System.setOut(new PrintStream(ps)); // output back to normal
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}
  }
  
  private String[][] readFrequencyTable(String filename){
	  String[][] table;
	  String helper = "";
	  try{
		  BufferedReader file = new BufferedReader(new FileReader(filename));
		  String line;
		  int linecount=0;
			while ((line = file.readLine()) != null) {
					helper.concat(line);
					helper.concat("\n");
					linecount++;
				}
			table = new String[linecount][3];
			int eol,e0,e1;
			int i,j;
			i=0;
			while(i<linecount){
				if (helper.length() <=0) break;
				eol = helper.indexOf("\n");
				j=eol-1;
				while(Character.isDigit(helper.charAt(j)) || helper.charAt(j)=='_'){
				j--;}
				e1=j;
				j--;
				while(Character.isDigit(helper.charAt(j)) || helper.charAt(j)=='.'){j--;}
				e0=j;
				//System.out.println("eol="+eol+" e1="+e1+" e0="+e0);
				if(e0<0 || e1<=e0+1 || eol<=e1+1){
					if (eol>=0) {
						helper=helper.substring(eol+1); 
						continue;
					}
				}
				table[i][0]=helper.substring(0,e0);
				table[i][1]=helper.substring(e0+1,e1);
				table[i][2]=helper.substring(e1+1,eol);
				helper=helper.substring(eol+1);
				System.out.println(table[i][0] + " " + table[i][1] + " " + table[i][2]);
				i++;
			}
		return table;
	  } catch (IOException e2) {
			e2.printStackTrace();
	  }
	  return null;
  }
  
  private float calcCoincidenceIndex(BufferedReader ciphertext) {
	  float back = -1.0f;
	  String text = bufferedReaderToString(ciphertext);
	  back = calcCoincidenceIndex(text);
	return back;
  }
  
  private float calcCoincidenceIndex(String text) {
	  float back = -1.0f;
	  createFrequencyTables("generatedAlphabet.alph", text, 1, 1, modulus);
	  readFrequencyTable("generated" + "1" + "-grams.alph.tab");
	return back;
  }
  
  private float calcPeriod(float ic) {
	  return 0.0f;
  }
  
  private String bufferedReaderToString(BufferedReader text) {
	String back  ="";
	String line;
	try{
		while ((line = text.readLine()) != null) {
			back.concat(line);
		}
	} catch (IOException e) {
		e.printStackTrace();
	}
	return back;
  }
  
  private void generateAlphabet(String text,String pathAlph){

		//Create alphabet
	    ArrayList<String> chars = new ArrayList<String>();
	    String symbol;
	    for(int i = 0; i<text.length();i++) {
	    	symbol = String.valueOf(text.charAt(i));
	    	int iFound = 0;
	    	System.out.println(">>>>>>>" + symbol);
	    	for(int j = 0;j< chars.size();j++) {
	    		if(symbol.equals(chars.get(j))) {
	    			iFound++;
	    		}
	    	}
	    	if(iFound == 0) {
	    		chars.add(symbol);
	    	}
	    }

	    BufferedWriter out;
	    symbol = "";
		try {
			out = new BufferedWriter(new FileWriter(pathAlph));
		    out.write("# Dieses Alphabet enthält alle Zeichen aus der gegebenen Datei.");
		    out.newLine();
		    out.write("# (Geschätzter) Modulus des Alphabets: " + chars.size());
		    out.newLine();
		    out.write("explicit");
		    out.newLine();
		    for (int i = 0; i < chars.size(); i++) {
				symbol = symbol + chars.get(i);
			}
		    //Zeichen
		    out.write(symbol);
		    out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
  }
  
  public int getGCD(int a, int b)
  {
     if (b==0) return a;
     return getGCD(b,a%b);
  }
  
  private int calcPossiblePeriod(String text, String ngram) {
	  int back = 0;
	  
	  //splitts text by the chosen ngram
	  String[] subStrings = text.split(ngram);
	  //gets periods between repeated ngram (first and last one are ignored)
	  int[] subLengths = new int[subStrings.length];
	  for(int i = 1; i<subStrings.length-1;i++) {
		  subLengths[i] = subStrings[i].length() + ngram.length();
	  }
	  //gets ggt() of all periods
	  int gcd = 0;
	  int newGCD = 0;
	  for(int i = 1;i<subLengths.length-1;i++) {
		  newGCD = getGCD(subLengths[i], subLengths[(i+1)%(subLengths.length-1)]);
		  if(i == 1) { gcd = newGCD ; }
		  if(gcd != newGCD) {
			  break;
		  }
		  gcd = newGCD;
	  }
	  
	  return back;
  }

}
