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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
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
	  String msg;
	  //TODOL This values need to be read in later
	  String cipher;
	  String alph = "generatedAlphabet.alph";
	  String textfile = "programmierer_enc.txt";
	  int minN = 1;
	  int maxN = 4;
	  int maxResults = 5;
	  
	  //TEST
	  //BufferedReader testIn = readFromFile("test.txt");
	  //String testText = bufferedReaderToString(testIn);
	  //generateAlphabet(testText, "test-alph.alph");
	  //createFrequencyTables("test-alph.alph","test.txt",1,1,3,"test-freq-");
	  
	  //Read text
	  BufferedReader textInput = readFromFile(textfile);
	  cipher = bufferedReaderToString(textInput);
	  
	  generateAlphabet(cipher,alph);
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean broken = false;
	  do{
		  boolean accepted = false;
		  do {
			  try{
				  msg = "Anhand des Chiffretextes wurde ein Modulus von " 	
					  + modulus + " geschätzt.\nBitte bestätigen Sie den Modulus " 
					  + "oder geben sie einen anderen Modulus ein: ";
				  System.out.println(msg);
				  int modu2 = Integer.parseInt(standardInput.readLine());
				  if (modu2==modulus) {
					  accepted = true;}
				  else if (modu2 < 1) {
				     System.out.println("Ein Modulus < 1 wird nicht akzeptiert. Bitte "
				              + "korrigieren Sie Ihre Eingabe.");
				     } else {
				          // Prüfe, ob zum eingegebenen Modulus ein Default-Alphabet existiert.
				          String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modu2);
				          generateAlphabet(defaultAlphabet,alph);
				          if (!defaultAlphabet.equals("")) {
				            msg = "Vordefiniertes Alphabet: '" + defaultAlphabet
				                + "'\nDieses vordefinierte Alphabet kann durch Angabe einer "
				                + "geeigneten Alphabet-Datei\nersetzt werden. Weitere "
				                + "Informationen finden Sie im Javadoc der Klasse\n'Character"
				                + "Mapping'.";
				            System.out.println(msg);
				            modulus=modu2;
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
			  } catch (NumberFormatException e){
				  System.out.println("Fehler beim Parsen des Modulus. Bitte korrigieren"
				            + " Sie Ihre Eingabe.");
			  } catch (IOException e) {
			        System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		        e.printStackTrace();
		        System.exit(1);
		      }
		  } while(!accepted);
	//Modulus ist nun festgelegt, jetzt machen wir Häufigkeitstabellen:
		  
	  createFrequencyTables(alph,textfile,minN,maxN,maxResults,"generated");
	  
	  msg="Möchten Sie Di-, Tri- oder 4-gramme analysieren? Bitte geben Sie 2, 3 oder 4 ein: ";
	  System.out.println(msg);
	  int xgram;
	  try{
		  xgram = Integer.parseInt(standardInput.readLine());
	  } catch (NumberFormatException e){
		  System.out.println("Fehler beim Parsen. Verwende default-Wert 3.");
		  xgram = 3;
	  } catch (IOException e) {
	      System.out.println("Fehler beim Parsen. Verwende default-Wert 3.");
	      xgram = 3;
      }
	  String table[][]= readFrequencyTable("generated"+xgram+"-grams.alph.tab");
	  int periods[] = new int[maxResults];
	  System.out.println("Die möglichen Perioden und zugehörige Koinzidenzindizes sind: ");
	  for(int i=0; i<maxResults;i++){
		periods[i] = calcPossiblePeriod(cipher, table[i][0]);
		System.out.println(periods[i] + "\t" + getSubtextCoincidenceIndex(cipher,periods[i]));
	  }
	  System.out.println("\nBitte wählen Sie eine Periode, deren Koinzidenzindex nahe bei 1 liegt,\n indem Sie sie eingeben: ");
	  int period;
	  try{
		  period = Integer.parseInt(standardInput.readLine());
	  } catch (NumberFormatException e){
		  System.out.println("Fehler beim Parsen. Verwende "+periods[0]);
		  period = periods[0];
	  } catch (IOException e) {
	      System.out.println("Fehler beim Parsen. Verwende "+periods[0]);
	      period = periods[0];
      }
	  
	  //Periode also keylength ist geraten, jetzt können wir beginnen, shifts zu füllen
	  keylength=period;
	  shifts = new int[keylength+1];
	  shifts[0]=modulus;
	  
	  char[] passwort = new char[period];
	  for(int i=0;i<period;i++){
		  passwort[i]=mostFreqChar(getSubtext(cipher,period,i));
		  System.out.println("Der häufigste Buchstabe im " + (i+1) 
				  + "ten Chiffreblock ist " + passwort[i]);
	  }
	  msg = "Bitte raten Sie eine Zuordnung indem Sie eine Folge von " + period + " Zeichen eingeben,\n" 
	  		+ "die Sie den häufigsten Buchstaben zuordnen wollen.\n" 
	  		+ "Wir empfehlen e, n und *.\n"
	  		+ "Für einen neuen Versuch, geben Sie zu viele oder wenige Zeichen ein.";
	  accepted = false;
	  do {
		  System.out.println(msg);
		  try {
			  String pass=standardInput.readLine();
			  if (pass.length()==period){
				  char[] zuord = pass.toCharArray();
				  for(int i=0;i<pass.length();i++){
					  shifts[i+1]=(passwort[i]-zuord[i])%modulus;
				  }
				  decipher(ciphertext, cleartext);
				  msg="Bitte überprüfen Sie die entschlüsselte Ausgabe.\n"
					  + "Gefällt Ihnen das Ergebnis? [y/n]";
				  System.out.println(msg);
				  String decide=standardInput.readLine();
				  if(decide.equalsIgnoreCase("y")) {accepted=true;}
				  else {System.out.println("Neuer Versuch.");}
			  }
			  else {
				  System.out.println("Suche wird abgebrochen.");
				  accepted=true;
			  }
		  } catch (IOException e){
			  System.out.println("Fehler beim Lesen von der Standardeingabe.\nNeuer Versuch.");
		  }
	  } while (!accepted);
	  
	  if(!broken) System.out.println("Ein neuer Brechungsversuch wird gestartet!");
	  }while(!broken);
	  System.out.println("Es ist Ihnen gelungen, die Chiffre zu brechen.\nHerzlichen Glückwunsch!");
  }

  private char mostFreqChar(String subtext){
      int character;
      HashMap<Integer, Integer> quantities = new HashMap<Integer, Integer>();
      for (int i=0;i<subtext.length();i++) {
    	character = subtext.charAt(i);
        character = charMap.mapChar(character);
        if (quantities.containsKey(character)) {
          quantities.put(character, quantities.get(character) + 1);
        } else {
          quantities.put(character, 1);
        }
      }
      int currKey = -1;
      int currValue = -1;
      int greatest = -1;
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
      return (char) charMap.remapChar(mostFrequented);
  }
  
  private double getSubtextCoincidenceIndex(String cipher, int period) {
	  String[] subtext= new String[period];
	  double CI = 0.0;
	  for(int i=0;i<period;i++){
		subtext[i] = getSubtext(cipher,period,i);
		CI = CI + calcCoincidenceIndex(subtext[i]);
	  }
	  return CI/period;
	}
  
  private String getSubtext(String cipher, int period, int offset){
	StringBuffer subtext = new StringBuffer("");
	while (offset<cipher.length()){
		subtext.append(cipher.charAt(offset));
		offset=offset+period;
	}
	return subtext.toString();
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
  
  private void createFrequencyTables(String alph, String textfile, int minN, int maxN, int maxResults,String praefix) {
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
	  	if(maxResults>textfile.length()){
	  		maxResults=textfile.length();
	  	}
		String[] frequencyTablesInput = new String[4];
		frequencyTablesInput[0] = alph;
		frequencyTablesInput[1] = textfile;
		frequencyTablesInput[2] = "" + minN;
		frequencyTablesInput[3] = "" + maxResults;
		//Create frequency tablesh
		try {
			//int maxN = Integer.parseInt(frequencyTablesInput[2]);
			PrintStream ps = System.out; // for bringing back old output
			for(int i = minN;i<=maxN;i++) {
				frequencyTablesInput[2] = ""+i;
				FileOutputStream fos = new FileOutputStream(praefix + i + "-grams.alph.tab");
				System.setOut(new PrintStream(fos));
				//sets the default output stream to a file while the frequency table is generated
				FrequencyTables.main(frequencyTablesInput);
				System.setOut(new PrintStream(ps)); // output back to normal
				fos.close();
			}
			
		} catch (IOException e1) {
			e1.printStackTrace();
		}
  }
  
  private String[][] readFrequencyTable(String filename){
	  String[][] table;
	  String[][] help;
	  StringBuffer help1 = new StringBuffer("");
	  String helper;
	  try{
		  BufferedReader file = new BufferedReader(new FileReader(filename));
		  String line;
		  int linecount=0;
			while ((line = file.readLine()) != null) {
					help1.append(line);
					help1.append("\n");
					linecount++;
				}
			helper=help1.toString();
			help = new String[linecount][3];
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
				help[i][0]=helper.substring(0,e0);
				help[i][1]=helper.substring(e0+1,e1);
				help[i][2]=helper.substring(e1+1,eol);
				helper=helper.substring(eol+1);
//				System.out.println(help[i][0] + " " + help[i][1] + " " + help[i][2]);
				i++;
			}
			linecount=i-1;
			table = new String[linecount][3];
			for(i=0;i<linecount;i++){
				table[i][0]=help[i][0];
				table[i][1]=help[i][1];
				table[i][2]=help[i][2];
				//System.out.println(help[i][0] + " " + help[i][1] + " " + help[i][2]);
			}
		return table;
	  } catch (IOException e2) {
			e2.printStackTrace();
	  }
	  return null;
  }
  
  private double calcCoincidenceIndex(BufferedReader ciphertext) {
	  double back = -1.0;
	  String text = bufferedReaderToString(ciphertext);
	  back = calcCoincidenceIndex(text);
	return back;
  }
  
  private double calcCoincidenceIndex(String text) {
	  double d = -1.0;
	  double N = (double) text.length();
	  if (N==1.0||N==0.0) {return 0;}
	  writeToFile("ictext.txt",text);
	  	  
	  generateAlphabet(bufferedReaderToString(readFromFile("ictext.txt")),"icAlph.alph");
	  createFrequencyTables("icAlph.alph", "ictext.txt", 1, 1, modulus,"ic");
	  String[][] table = readFrequencyTable("ic"+ "1" + "-grams.alph.tab");
	  int n = table.length;
	  double IC = 0;
	  for(int i=0;i<n;i++){
		  IC=IC+Double.parseDouble(table[i][1])/100*(Double.parseDouble(table[i][1])/100-1);
	  }
	  IC=IC/(N*(N-1));
	  d=(N*(IC-1.0/n))/((N-1)*IC-N/n+IC);
	return d;
  }
  
  private String bufferedReaderToString(BufferedReader text) {
	StringBuffer helper = new StringBuffer("");
	String line;
	try{
		while ((line = text.readLine()) != null) {
//			System.out.println(">>>>BufferedReaderToString Loop: " + line);
			helper.append(line);
		}
//		System.out.println(">>>>BufferedReaderToString Return: " + helper);
	} catch (IOException e) {
		e.printStackTrace();
	}
	return helper.toString();
  }
  
  private void generateAlphabet(String text,String pathAlph){
		//Create alphabet
	    ArrayList<String> chars = new ArrayList<String>();
	    String symbol;
	    for(int i = 0; i<text.length();i++) {
	    	symbol = String.valueOf(text.charAt(i));
	    	int iFound = 0;
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
		    modulus=chars.size();
		} catch (IOException e) {
			e.printStackTrace();
		}
  }
  
  public int getGCD(int a, int b)
  {
	 int Tmp;
	 if(a<b) {
		 Tmp = a;
		 a = b;
		 b = Tmp;
	 }
     while (b!=0){
    	 Tmp=a%b;
    	 a=b;
    	 b=Tmp;
     }
     return a;
  }
  
  private int calcPossiblePeriod(String text, String ngram) {
	  //splitts text by the chosen ngram
	  String[] subStrings = text.split(ngram);
	  //gets periods between repeated ngram (first and last one are ignored)
	  int[] subLengths = new int[subStrings.length];
	  for(int i = 1; i<subStrings.length;i++) {
		  subLengths[i] = subStrings[i].length() + ngram.length();
		  //System.out.println(subLengths[i]);
	  }
	  //gets ggt() of all periods
	  int GCD[] = new int[subLengths.length];
	  GCD[0]=subLengths[subLengths.length-1];
	  for(int i = 1;i<subLengths.length;i++) {
		  GCD[i] = getGCD(subLengths[i],subLengths[(i+1)%(subLengths.length)]);
	  }
	  GCD[0]=getGCD(GCD[subLengths.length-1],GCD[0]);
	  return GCD[0];
  }
  
  private BufferedReader readFromFile(String file) {
	  BufferedReader textInput = null;
	try {
		textInput = new BufferedReader(new FileReader(file));
	} catch (FileNotFoundException e) {
		e.printStackTrace();
	}
	  return textInput;
  }
  
  private void writeToFile(String filename,String text) {
	  try {
		  BufferedWriter out = new BufferedWriter(new FileWriter(filename));
		  out.write(text);
		  out.close();
	  } catch (IOException e){
		  e.printStackTrace();
	  }
  }

}
