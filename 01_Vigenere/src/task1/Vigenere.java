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
import java.io.File;
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
	
	private boolean broken = true;
	
	private final boolean DEBUG = true;
	
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
	  if(DEBUG) System.out.println(">>>breakCipher called");
	  
//	  //Test IC
//	  if(DEBUG) {
//		String sTmp = "abadeffhaj";
//		System.out.print(">>>> String: " + sTmp);
//		System.out.print("\t Länge: " + sTmp.length());
//		System.out.print("\t oldIC: " + calcCoincidenceIndex(sTmp));
//		System.out.print("\t IC: " + calcIC(sTmp));
//		System.out.print("\t approx p: " + calcPeriod(calcIC(sTmp), sTmp));
//		System.out.println();
//		System.exit(0);
//	  }
	  
//	  //Test writeToFile
//	  if(DEBUG) {
//		  writeToFile("test.txt", "blah2");
//		  writeToFile("test.txt", "blah3");
//		  System.exit(0);
//	  }
	  
	  //Test getSubtext
//	  if(DEBUG) {
//		  String sTmp = bufferedReaderToString(readFromFile("test.txt"));
//		  double dTmp = getSubtextCoincidenceIndex(sTmp, 10);
//		  String sTmp2 = getSubtext(sTmp,10,0);
//		  System.out.print("#### " + dTmp);
//		  System.out.print("\t" + sTmp2);
//		  System.out.println();
//		  for (int i = 0; i < 11; i++) {
//			sTmp2 = getSubtext(sTmp,10,i);
//			System.out.println(i + " \t" + sTmp2);			
//		  }
//		  System.out.println();
//		  System.exit(0);
//	  }

//	  if(DEBUG){
//		  String s = "\n";
//		  System.out.println((int)'\n' + "" +  '\n' + "blah \t" + s);
//		  System.out.println("blah");
//		  System.exit(0);
//	  }
	  
	  //safe buffered ciphertext to file
	  //writeToFile("read-cipher.txt", bufferedReaderToString(ciphertext));
	  //ciphertext = readFromFile("read-cipher.txt");
	  
	  String msg;
	  int modu2 = modulus;
	  String cipher;
	  String alph = "generatedAlphabet.alph";
	  String textfile = launcher.getCiphertextFile().toString(); 
	  String textfile2 = launcher.getCleartextFile().toString();
	  //"programmierer_enc.txt";
	  
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
	  broken = false;
	  do{
		  boolean accepted = false;
		  do {
			  try{
				  msg = "Anhand des Chiffretextes wurde ein Modulus von " 	
					  + modulus + " geschätzt.\nBitte bestätigen Sie den Modulus " 
					  + "oder geben sie einen anderen Modulus ein: ";
				  System.out.println(msg);
				  modu2 = Integer.parseInt(standardInput.readLine());
				  if (modu2==modulus) {
					  accepted = true;}
				  else if (modu2 < 1) {
				     System.out.println("Ein Modulus < 1 wird nicht akzeptiert. Bitte "
				              + "korrigieren Sie Ihre Eingabe.");
				     } else {
				          // Prüfe, ob zum eingegebenen Modulus ein Default-Alphabet existiert.
				          String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modu2);
				          if (!defaultAlphabet.equals("")) {
				        	charMap = new CharacterMapping(modu2);		
				            msg = "Vordefiniertes Alphabet: '" + defaultAlphabet
				                + "'\nDieses vordefinierte Alphabet kann durch Angabe einer "
				                + "geeigneten Alphabet-Datei\nersetzt werden. Weitere "
				                + "Informationen finden Sie im Javadoc der Klasse\n'Character"
				                + "Mapping'.";
				            System.out.println(msg);
				            //System.out.println(">>> modulus=modu2: " + modu2);
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
	  createFrequencyTables(charMap, textfile, 1,1,modulus,"");  
	  createFrequencyTables(charMap,textfile,2,4,5,"generated");
	  
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

	  //System.out.println(">>>a modulus L145: " + modulus);
	  String table[][]= readFrequencyTable("generated"+xgram+"-grams.alph.tab");
	  //System.out.println(">>>table.length="+table.length);
	  System.out.println("Die möglichen Perioden und zugehörige Koinzidenzindizes sind: ");
	  //mögliche Perioden in HashMap speichern, häufigste 5 finden, landen in peri[]
	  HashMap<Integer, Integer> quantities = new HashMap<Integer, Integer>();
	  int max=1;
	  for(int i=0; i<5;i++){
		int[] periods = calcPossiblePeriod(cipher, table[i][0]);
		for(int j=0;j<periods.length;j++){
			if (!quantities.containsKey(periods[j])){
				quantities.put(periods[j],1);
			} else {
				quantities.put(periods[j], quantities.get(periods[j]) + 1);
				if(quantities.get(periods[j])>max){
					max=quantities.get(periods[j]);
				}
			}
		}
	  }
	  int currKey = -1;
      int currValue = -1;
      int[] freq = {-1,-1,-1,-1,-1};
      int[] peri = {1,1,1,1,1};
      Iterator<Integer> it = quantities.keySet().iterator();
      while (it.hasNext()) {
        currKey = it.next();
        currValue = quantities.get(currKey);
        if (currValue > freq[0]) {
          freq[4]=freq[3]; freq[3]=freq[2]; freq[2]=freq[1]; freq[1]=freq[0];
          freq[0]=currValue;
          peri[4]=peri[3]; peri[3]=peri[2]; peri[2]=peri[1]; peri[1]=peri[0];
          peri[0] = currKey;
        } else if (currValue > freq[1]){
        	freq[4]=freq[3]; freq[3]=freq[2]; freq[2]=freq[1];
            freq[1]=currValue;
            peri[4]=peri[3]; peri[3]=peri[2]; peri[2]=peri[1];
            peri[1] = currKey;
        } else if (currValue > freq[2]){
        	freq[4]=freq[3]; freq[3]=freq[2];
            freq[2]=currValue;
            peri[4]=peri[3]; peri[3]=peri[2];
            peri[2] = currKey;
        } else if (currValue > freq[3]){
        	freq[4]=freq[3];
            freq[3]=currValue;
            peri[4]=peri[3];
            peri[3] = currKey;
        } else if (currValue > freq[4]){
        	freq[4]=currValue;
        	peri[4] = currKey;
        }
      }
      for(int i=0;i<5;i++){
		System.out.print(peri[i] + "\t"); 
		System.out.println(getSubtextCoincidenceIndex(cipher,peri[i]));
      }

	  //System.out.println(">>>a modulus vor periodenfrage: " + modulus);
	  System.out.println("\nBitte wählen Sie eine Periode, deren Koinzidenzindex nahe bei 1 liegt,\n indem Sie sie eingeben: ");
	  int period;
	  try{
		  period = Integer.parseInt(standardInput.readLine());
	  } catch (NumberFormatException e){
		  System.out.println("Fehler beim Parsen. Verwende "+peri[1]);
		  period = peri[1];
	  } catch (IOException e) {
	      System.out.println("Fehler beim Parsen. Verwende "+peri[1]);
	      period = peri[1];
      }
	  
	  //Periode also keylength ist geraten, jetzt können wir beginnen, shifts zu füllen
	  keylength=period;
	  shifts = new int[keylength+1];
	  //System.out.println(">>>a modulus: " + modulus);
	  shifts[0]=modu2;
	  
	  char[][] passwort = new char[period][2];
	  for(int i=0;i<period;i++){
		  passwort[i]=mostFreqChar(getSubtext(cipher,period,i));
		  System.out.println("Die häufigsten Buchstaben im " + (i+1) 
				  + "ten Chiffreblock sind \t" 
				  + passwort[i][0] + " (" + (charMap.mapChar((int)passwort[i][0]))+  ") und \t"
				  + passwort[i][1]+ " (" + (charMap.mapChar((int)passwort[i][1]))+  ")");
	  }
	  
	  accepted = false;
	  writeToFile("symbols.txt", charMap.toString());
	  String pass;
	  String[] sArray = {"e","n","i","*"," "};
	  //if(DEBUG) {System.out.println(">>>>breakCipher Passwortzuordnung raten");}
	  do {
		  //if(DEBUG){System.out.println(">>>>breakCipher Passwortzuordnung raten (Loop)"); }
		  msg = "Bitte raten Sie eine Zuordnung indem Sie eine Folge von " + period + " Zeichen eingeben,\n" 
	  		+ "die Sie den häufigsten Buchstaben zuordnen wollen.\n" 
	  		+ "Wir empfehlen "
	  		+ "e (" + charMap.mapChar((int)sArray[0].charAt(0)) + "), "
	  		+ "n (" + charMap.mapChar((int)sArray[1].charAt(0)) + "), "
	  		+ "i (" + charMap.mapChar((int)sArray[2].charAt(0)) + "), "
	  		+ "* (" + charMap.mapChar((int)sArray[3].charAt(0)) + ") und "
	  		+ "leerzeichen  (" + charMap.mapChar((int)sArray[4].charAt(0)) + ").\n"
	  		+ "Für eine Übersicht der Zeichen ziehen Sie bitte die Datei symbols.txt zu rate.\n"
	  		+ "Für einen neuen Versuch, geben Sie zu viele oder wenige Zeichen ein.";
		  System.out.println(msg);
		  try {
			  pass=standardInput.readLine();
			  if (pass.length()==period){
				  char[] zuord = pass.toCharArray();
				  for(int i=0;i<pass.length();i++){
					  //Cipher-Klar=Key; Klar+Key=Cipher; Cipher-Key=Klar
					  shifts[i+1]=(charMap.mapChar(passwort[i][0]) - charMap.mapChar(zuord[i]) + modu2)%modu2;
//					  if(shifts[i+1] <0) {
//						  shifts[i+1] = modu2 + shifts[i+1];
//					  }
					  if(DEBUG) { 
						  System.out.print(">>>breakCipher Verschiebung eingegeben: " + shifts[i+1] + "\t");
						  System.out.print(charMap.mapChar(passwort[i][0]) + "\t");
						  System.out.print(charMap.mapChar(zuord[i]) + "\t");
						  System.out.print(modu2 + "\t");
						  System.out.print(Arrays.toString(passwort[i]) + "\t");
						  System.out.print(zuord[i]);
						  System.out.println();
					  }
				  }
				  String sTmp = ""+modu2+"\n"+period;
				  keylength=period;
				  for(int i = 1; i<shifts.length;i++) {
					  sTmp = sTmp + "\n" + shifts[i];
				  }
				  writeToFile("key_break.txt", sTmp);
				  BufferedReader key = readFromFile("key_break.txt");
				  readKey(key);
				  //key.close();
				  //modulus = modu2;
				  decipher(readFromFile(textfile), new BufferedWriter(new FileWriter(launcher.getCleartextFile())));
//				  if(DEBUG) {System.out.println(">>>breakCipher nach decipher shifts: " + Arrays.toString(shifts));};
				  msg="Bitte überprüfen Sie die entschlüsselte Ausgabe:";
				  System.out.println(msg);
				  //Prints the first symbols of the broken text
				  BufferedReader rff = readFromFile("cleartext_broken.txt");
				  String sRFF = bufferedReaderToString(rff);
				  System.out.println("Ausgabe (Auszug):  " + sRFF.substring(0, 20) + "[...]");
				  msg="Gefällt Ihnen das Ergebnis? [y/n]";
				  System.out.println(msg);
				  String decide=standardInput.readLine();
				  if(decide.equalsIgnoreCase("y")) {
					  accepted=true;
					  broken=true;
				  }
				  else {
					  System.out.println("Neuer Versuch.");
					  broken=false;
					  accepted=false;
				  }
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
	  
	  //Calculate password
//	  if(DEBUG) {
//		  System.out.println(">>>>breakCipher Shift bei passwort Raten");
//		  for(int i = 0;i<shifts.length;i++)
//			  System.out.println(">>>>" + shifts[i]);		  
//	  }
	  BufferedReader rff = readFromFile("cleartext_broken.txt");
	  String sRFF = bufferedReaderToString(rff);
	  sRFF = sRFF.substring(0, shifts.length-1);
	  String guessedPass = "";
	  for(int i = 1;i<shifts.length;i++) {
		  int rmc = charMap.remapChar(shifts[i]);
		  String srmc = String.valueOf((char)rmc);
		  guessedPass = guessedPass + srmc;
	  }
	  System.out.println("Das vermutete Passwort lautet:  " + guessedPass);
	  
	  try {
		standardInput.close();
	} catch (IOException e) {
		//e.printStackTrace();
	}
  }

  private char[] mostFreqChar(String subtext){
	  if(DEBUG) { System.out.println(">>>>mostFreqChar called"); }
	  //System.out.println(">>>Ich bin mostFreqChar");
      char[] most=new char[2];
      writeToFile("ictextMostFreqChar.txt",subtext);
      //System.out.println(">>>ictext neu geschrieben");
      String praefix = "ic-";
      writeToFile(praefix + "Alph.alph",charMap.toString());
	  createFrequencyTables(charMap, "ictextMostFreqChar.txt", 1, 1, 5,praefix);
	  //System.out.println(">>>ic1-grams neu geschrieben");
	  String[][] table = readFrequencyTable(praefix +  "1" + "-grams.alph.tab");
	  //System.out.println(">>>tabelle eingelesen "+ table[0][0]+table[1][0]);
      most[0]=table[0][0].charAt(0);
      most[1]=table[1][0].charAt(0);
      //System.out.println(">>>in char umgewandelt"+most.toString());
/*      int character;
      HashMap<Integer, Integer> quantities = new HashMap<Integer, Integer>();
      for (int i=0;i<subtext.length();i++) {
    	character = subtext.charAt(i);
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
      }*/
      return most;
  }
  
  private double getSubtextCoincidenceIndex(String cipher, int period) {
	  String[] subtext= new String[period];
	  double CI = 0.0;
	  int p=0;
	  double dummy;
	  for(int i=0;i<period;i++){
		subtext[i] = getSubtext(cipher,period,i);
		dummy=calcCoincidenceIndex(subtext[i]);
		if(dummy!=-1.0){
			CI+=dummy;
			p++;
		}
	  }
	  if (p==0) {return -1.0;}
	  return CI/p;
	}
  
  private String getSubtext(String cipher, int period, int offset){
	String subtext = "";
	while (offset<cipher.length()){
		subtext=subtext+cipher.charAt(offset);
		offset=offset+period;
	}
	//System.out.println(">>>"+subtext);
	return subtext;
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
	  if(DEBUG) { System.out.println(">>>decipher called"); }
      if(DEBUG) System.out.println(">>>decipher used Alphabet: " + charMap.getAlphabetFile());

	  writeToFile("symbols-dec.txt", charMap.toString());
    // An dieser Stelle könnte man alle Zeichen, die aus der Klartextdatei
    // gelesen werden, in Klein- bzw. Großbuchstaben umwandeln lassen:
    // charMap.setConvertToLowerCase();
    // charMap.setConvertToUpperCase();

//	if(DEBUG) {
//		try {
//			System.out.println(">>>decipher test BufferedReader: L423 " + ciphertext.ready() );
//		} catch (IOException e1) {
//			e1.printStackTrace();
//			System.out.println(">>>decipher BufferedReader für ciphertext tot?!");
//		}		
//	}
	
    try {
      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      // 'characterSkipped' zeigt an, daß ein aus der Klartextdatei gelesenes
      // Zeichen mit dem gewählten Alphabet nicht abgebildet werden konnte.
      boolean characterSkipped = false;
      // Lese zeichenweise aus der Klartextdatei, bis das Dateiende erreicht
      // ist. Der Buchstabe a wird z.B. als ein Wert von 97 gelesen.
      int counter=1;
      int i=0;

//	if(DEBUG) {
//		try {
//			System.out.println(">>>decipher test BufferedReader: L442 " + ciphertext.ready() );
//		} catch (IOException e1) {
//			e1.printStackTrace();
//			System.out.println(">>>decipher BufferedReader für ciphertext tot L445");
//		}		
//	}
      while ((character = ciphertext.read()) != -1) {
//    	if (DEBUG && i<11) { System.out.print(">>>"+(char)character); }
        // Bilde 'character' auf dessen interne Darstellung ab, d.h. auf einen
        // Wert der Menge {0, 1, ..., Modulus - 1}. Ist z.B. a der erste
        // Buchstabe des Alphabets, wird die gelesene 97 auf 0 abgebildet:
        // mapChar(97) = 0.
        character = charMap.mapChar(character);
//        if (DEBUG && i<11) { System.out.print("\t -->>>mapped to: "+character); }
        if (character != -1) {
          // Das gelesene Zeichen ist im benutzten Alphabet enthalten und konnte
          // abgebildet werden. Die folgende Quellcode-Zeile stellt den Kern der
          // Caesar-Chiffrierung dar: Addiere zu (der internen Darstellung von)
          // 'character' zyklisch den 'shift' hinzu.
          character = (character - shifts[counter] + modulus) % modulus;
//          if (DEBUG && i<11) { System.out.print("\t -->>>deciphered to: "+character); }
          // Das nun chiffrierte Zeichen wird von der internen Darstellung in
          // die Dateikodierung konvertiert. Ist z.B. 1 das Ergebnis der
          // Verschlüsselung (also die interne Darstellung für b), so wird dies
          // konvertiert zu 98: remapChar(1) = 98. Der Wert 98 wird schließlich
          // in die Chiffretextdatei geschrieben.
          character = charMap.remapChar(character);
//          if (DEBUG && i<11) { System.out.print("\t -->>>remapped to: "+(char)character); }
//          if (DEBUG && i<11) { System.out.print("\t -->>> with shift: " +shifts[counter]); }
//          if (DEBUG && i<11) { System.out.println("\t -->>> with modulus: " +modulus); }
          cleartext.write(character);
          i++;
        } else {
          // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
          characterSkipped = true;
          //if(DEBUG) { System.out.println(">>>ooops not found"); }
        }
        counter=(counter+1)%(keylength+1);
        if(counter==0) counter=1;
      }
//  	if(DEBUG) {
//		try {
//			System.out.println(">>>decipher test BufferedReader: L484 " + ciphertext.ready() );
//		} catch (IOException e1) {
//			e1.printStackTrace();
//			System.out.println(">>>decipher BufferedReader für ciphertext tot L487");
//		}		
//	}
      if(DEBUG) { System.out.println("\n>>>Ich bin decipher und habe alles gelesen!"); }
      if (characterSkipped) {
        System.out.println("Warnung: Mindestens ein Zeichen aus der "
            + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde "
            + "überlesen.");
      }

      //erst schließen, wenn kein weiterer Zugriff erforderlich ist!
      if(broken) {
          cleartext.close();
          ciphertext.close(); 
          System.out.println("Zugriff auf Cipher- und Klartext geschlossen.");
      }
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
          + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
        
//    if(DEBUG) { System.out.println(">>>decipher finished shifts:" + Arrays.toString(shifts)); }
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
	  

	  writeToFile("symbols-enc.txt", charMap.toString());

    try {
      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      // 'characterSkipped' zeigt an, daß ein aus der Klartextdatei gelesenes
      // Zeichen mit dem gewählten Alphabet nicht abgebildet werden konnte.
      boolean characterSkipped = false;
      // Lese zeichenweise aus der Klartextdatei, bis das Dateiende erreicht
      // ist. Der Buchstabe a wird z.B. als ein Wert von 97 gelesen.
      int counter=1;
      //if(DEBUG) System.out.println(">>>encipher used Alphabet: " + charMap.getAlphabetFile().getName());
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
          counter=(counter+1)%(keylength+1);
          if(counter==0) counter=1;
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
      System.out.println("Zugriff auf Klar- und Ciphertext geschlossen.");
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
	  if(DEBUG) System.out.println(">>>makeKey called");


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
	  if(DEBUG) System.out.println(">>>readKey called");

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
	  if(DEBUG) System.out.println(">>>writeKey called");

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
  
  private void createFrequencyTables(CharacterMapping charMap, String textfile, int minN, int maxN, int maxResults,String praefix) {
	  String alph;
	  int modu3=charMap.getModulusFromAlphabet();
	  //System.out.println(">>>modu3 is "+modu3);
	  if (modu3==26||modu3==27||modu3==30||modu3==31||modu3==33||modu3==90||modu3==91){
		  alph="../alphabet/default"+modu3+".alph";
	  } else {
		  alph="generatedAlphabet.alph";
	  }
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
				PrintStream psNew = new PrintStream(fos);
				System.setOut(psNew);
				//sets the default output stream to a file while the frequency table is generated
				FrequencyTables.main(frequencyTablesInput);
				System.setOut(new PrintStream(ps)); // output back to normal
				psNew.close();
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
			linecount=i;
			//System.out.println(">>>Die Tabelle hat "+linecount+" Zeilen.");
			if(linecount<1) return null;
			table = new String[linecount][3];
			for(i=0;i<linecount;i++){
				table[i][0]=help[i][0];
				table[i][1]=help[i][1];
				table[i][2]=help[i][2];
				//System.out.println(help[i][0] + " " + help[i][1] + " " + help[i][2]);
			}
		file.close();
		return table;
	  } catch (IOException e2) {
			e2.printStackTrace();
	  }
	  return null;
  }
  
  private double calcIC(BufferedReader ciphertext) {
	  double back = -1.0;
	  String text = bufferedReaderToString(ciphertext);
	  back = calcIC(text);
	return back;
  }
  
  private String[][] getAbsoluteFrequency(String text) {
	//if(DEBUG) { System.out.println(">>>getAbsoluteFrequency called"); }
	String[][] back;  
	ArrayList<String> foundSymbols = new ArrayList<String>();
	String sTmp = "";
	
	//Symbole suchen
	for(int i = 0;i<text.length();i++) {
		if(!foundSymbols.contains(String.valueOf(text.charAt(i)))) {
			sTmp = "" + String.valueOf(text.charAt(i));
			foundSymbols.add(sTmp);
		}
	}
	//if(DEBUG) System.out.println(">>>> " + foundSymbols.toString());
	
	//Symbole zählen
	ArrayList<Integer> countSymbols = new ArrayList<Integer>();
	for(int i = 0;i<foundSymbols.size();i++) {
		countSymbols.add(0); //erzeuge Zaehlerliste fuer Symbole
	}
	for(int i = 0;i<text.length();i++) {
		int index = foundSymbols.indexOf(String.valueOf(text.charAt(i)));
		int count = 0;
		count = countSymbols.get(index);
		countSymbols.set(index, count + 1);
	}
	//if(DEBUG) System.out.println(">>>> " + countSymbols.toString());
	
	//Erzeuge return statement
	back = new String[foundSymbols.size()][2];
	for(int i = 0;i<foundSymbols.size();i++) {
		back[i][0] = foundSymbols.get(i);
		back[i][1] = "" + countSymbols.get(i);
		//if(DEBUG) System.out.print(">>>> " + Arrays.toString(back[i]) + " ; ");
	}	
	
	return back;	  
  }
  /**
   * Achtung, macht dummes Zeug - Periode ist immer 1.0, weil sich alles wegkürzt.
   * @param ic
   * @param text
   * @return
   * 
   * @deprecated
   */
  private double calcPeriod(double ic,String text) {
	  double back = -1.0; // approximierte Periodenlaenge
	  
	  String[][] sAbsoluteFreqency = getAbsoluteFrequency(text);
	  double dN = text.length();
	  double dn = sAbsoluteFreqency.length;
	  
	  back = (ic - 1.0 / dn) * dN;
	  back = back / (((dN - 1.0) * ic) - (1.0/dn * dN) + ic);
	  
	  return back;
  }
  
  private double calcIC(String text) {
	  //if(DEBUG) System.out.println(">>>calcIC called");
	  double ic = -1.0;
	  
	  //Hole absolute Häufigkeiten der Buchstaben.
	  String[][] sAbsoluteFreqency = getAbsoluteFrequency(text);

	  //Anzahl der einzelnen Buchstaben
	  double iSum = 0;
	  double[] iF = new double[sAbsoluteFreqency.length];
	  for(int i = 0;i<sAbsoluteFreqency.length;i++) {
		  iF[i] = Integer.parseInt(sAbsoluteFreqency[i][1]);
	  }
	  
	  for(int i = 0;i<iF.length;i++) {
		  iSum = iSum + iF[i] * (iF[i] - 1);
	  }
	  double iN = text.length();	//Laenge des Textes

	  //if(DEBUG) System.out.println(">>>> iSum = " + iSum);
	  //if(DEBUG) System.out.println(">>>> iN = " + iN);
	  
	  ic = iSum / (iN * (iN - 1.0));
	  //if(DEBUG) System.out.println("IC = " + ic);
	  
	  return ic;
  }
  
  private double calcCoincidenceIndex(String text) {
	  double d = -1.0;
	  double N = (double) text.length();
	  if (N==1.0||N==0.0) {return -1.0;}
	  //System.out.println(">>>N"+N);
	  writeToFile("ictext.txt",text);
	  createFrequencyTables(charMap, "ictext.txt", 1, 1, modulus,"ic");
	  String[][] table = readFrequencyTable("ic" + "1" + "-grams.alph.tab");
	  String[][] table2 = readFrequencyTable("1-grams.alph.tab");
	  if(table!=null && table2!=null){
		  int n = table.length;
		  int m = table2.length;
		  double IC = 0;
		  double psquared = 0;
		  //SUM(p^2 - 1/n)
		  for(int i=0;i<m;i++){
			  psquared=psquared+Double.parseDouble(table2[i][1])*Double.parseDouble(table2[i][1])/10000;
		  }
		  for(int i=0;i<n;i++){
			  IC=IC+Double.parseDouble(table[i][1])/100*N*(Double.parseDouble(table[i][1])/100*N-1);
		  }
		  IC=IC/(N*(N-1));
		  //System.out.print(">>>p² "+psquared+"\t");
		  //System.out.print(">>>IC "+IC+"\t");
		  d=(N*(psquared-1.0/n))/((N-1.0)*IC-N/n+psquared);
	  }
	  //System.out.println(">>>d "+d);
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
  
  private int getGCD(int a, int b)
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
  
  private int[] calcPossiblePeriod(String text, String ngram) {
	  //splitts text by the chosen ngram
	  String[] subStrings = text.split(ngram);
	  //gets periods between repeated ngram (first and last one are ignored)
	  int[] subLengths = new int[subStrings.length];
	  for(int i = 1; i<subStrings.length;i++) {
		  subLengths[i] = subStrings[i].length() + ngram.length();
		  //System.out.println(subLengths[i]);
	  }
	  //gets ggt() of all periods
	  int GCD[] = new int[subLengths.length-1];
	  GCD[0]=subLengths[subLengths.length-1];
	  for(int i = 1;i<subLengths.length-1;i++) {
		  GCD[i] = getGCD(subLengths[i],subLengths[(i+1)%(subLengths.length-1)]);
	  }
	  GCD[0]=getGCD(GCD[subLengths.length-2],GCD[0]);
	  return GCD;
  }
  
  private BufferedReader readFromFile(String file) {
	  BufferedReader textInput = null;
	  try {
		textInput = new BufferedReader(new FileReader(file));
		//textInput.close(); //has to be open!!
	  } catch (FileNotFoundException e) {
		e.printStackTrace();
	  }
	  return textInput;
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
