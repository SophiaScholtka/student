/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        IDEA.java
 * Beschreibung: Dummy-Implementierung des International Data Encryption
 *               Algorithm (IDEA)
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {
	final boolean DEBUG = true;
	short[] ideaKey = new short[8];
  /**
   * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
   * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
   * <code>cleartext</code>.
   *
   * @param ciphertext
   * Der FileInputStream, der den Chiffretext liefert.
   * @param cleartext
   * Der FileOutputStream, in den der Klartext geschrieben werden soll.
   */
  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
	  //TODO nimm den schlüssel und setze die Tabelle auf Seite 59 um, um daraus den dechiffrier-Schlüssel zu erhalten
	  //TODO benutze dann einfach encipher mit dem Dechiffrierschlüssel
  }

  /**
   * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
   * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
   * <code>ciphertext</code>.
   * 
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   * Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
   */
  public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {
	  
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {
	  //User fragen ob eigener oder Zufallskey
	  //128-bit = 8 char Schlüssel einlesen oder auswürfeln
	  String originalKey = "abcdefghijklmnop";
	  ideaKey = stringKeytoShortKey(originalKey);
	  if (DEBUG) {
		  System.out.print(">>>Schlüssel:");
		  for (int i=0;i<ideaKey.length;i++) System.out.print(" " + ideaKey[i]);
		  System.out.println();
	  }
  }
  /** 
   * Schlüsselexpansion nach Algorithmus 4.1
   * @param tmpKey
   * @return
   */
  private short[][] expandKey(short[] tmpKey) {
	  short[][] expandedKey=new short[9][6];
	  int index1,index2;
	  //Teile Key in acht 16-Bit-Teilschlüssel auf und weise diese direkt den ersten 8 Teilschlüsseln zu
	  for(int i=0;i<8;i++){
		  index1=i/6;
		  index2=i%6;
		  expandedKey[index1][index2]=(short) tmpKey[i];
	  }
	  /* while noch nicht alle 52 teilschlüssel zugewiesen,
	   * führe auf Key einen zyklischen Linksshift um 25 Positionen durch,
	   * teile das Ergebnis in acht 16-Bit-Blöcke ein
	   * weise das Ergebnis den nächsten 8 (oder im letzten Schritt 4) Teilschlüsseln zu
	   */
	  
	  //Ich schreib es lieber nicht als while sondern als for-Schleife - Schlüssel 8 bis 47
	  for (int i=1;i<6;i++){
		  tmpKey = shiftKey(tmpKey);
		  for (int j=0;j<8;j++){
			  index1=(i*8+j)/6;
			  index2=(i*8+j)%6;
			  expandedKey[index1][index2]=tmpKey[j];
		  }
	  }
	  //Schlüssel 48 bis 52
	  tmpKey=shiftKey(tmpKey);
	  for (int i=0;i<4;i++){
		  expandedKey[8][i]=tmpKey[i];
	  }
	  if (DEBUG) {
		  System.out.print(">>>Expandierter Schlüssel:");
		  for (int i=0;i<9;i++) {for(int j=0;j<6;j++) System.out.print(" " + expandedKey[i][j]);}
		  System.out.println();
	  }
	  return expandedKey;
  }

  //1 short = 2 byte = 16 bit ; 	–2^15 bis 2^15 – 1 (–32768...32767) 
  private short[] shiftKey(short[] key) {
	  short[] back=key;
	  short tmp;
	  int l=back.length;
	// zyklisch um 25 = 16+9 bits nach links verschieben und zurück geben
	  for(int i=0;i<l;i++){
		  //ganzzahlige div, schreibt die hinteren 7 bits von key[i+1] nach vorne in back[i] (restliche 9 bits sind 0)
		  back[i]= (short) (key[(i+1)%l]/((int) Math.pow(2, 9)));
		  //modulus, schreibt die vorderen 9 bits von key[i+2] in tmp
		  tmp= (short) (key[(i+2)%l]%((int)Math.pow(2, 9)));
		  //multiplikation, schreibt die 9 bits aus tmp an position 7 bis 15 von back[i] (vordere 7 bits sind 0)
		  back[i] += (short)(tmp*((int)Math.pow(2, 7)));
	  }
	return back;
}

private short[] stringKeytoShortKey(String originalKey) {
	if(originalKey.length() != 16){
		System.out.println("Fehler: Falsche Schlüssellänge! Abbruch.");
		System.exit(0);
	}
	short[] back = new short[8];
	byte t1,t2; //Jedes Ascii-Zeichen ist max 1 Byte groß
	for (int i=0;i<8;i++){
		t1=(byte) originalKey.charAt(2*i);
		t2=(byte) originalKey.charAt(2*i+1);
		//schreibe 2 Byte hintereinander in ein Short, indem das erste mit 2^8 multipliziert wird
		back[i]=(short) ((int) Math.pow(2, 8)*t1 + t2);
	}
	return back;
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
		  for(int i=0;i<8;i++){
			  ideaKey[i] = Short.parseShort(key.readLine());
		  }
	  } catch (IOException e){
		  System.out.println("Fehler beim Parsen der Schlüsseldatei.");
		  System.exit(0);
	  }
	  if (DEBUG) {
		 System.out.println(">>>Schlüssel: " + Arrays.toString(ideaKey));
		 expandKey(ideaKey);
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
		  for (int i=0;i<ideaKey.length;i++){
			  key.write(ideaKey[i] + "\n");
		  }
		  key.close();
	  } catch (IOException e) {
		  e.printStackTrace();
		  System.exit(0);
	  }
  }
  
  //1 byte = 8 bit; –2^7 bis 2^7 – 1 (–128...127) 
  //1 short = 2 byte = 16 bit ; 	–2^15 bis 2^15 – 1 (–32768...32767) 
  //1 char = 2 byte = 16 bit ; 16-Bit Unicode Zeichen (0x0000...0xffff)
  // ^ bitweises exklusives Oder (Xor)
  // | bitweises Oder
  // & bitweises Und
  
  /**
   * Bitweise XOR	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message
   * @param key
   * @return
   */
  private short calcBitwiseXor(short message, short key) {
	  short back;
	  back = (short) (message ^ key);
	  
	  return back;
  }
  
  /**
   * Addition mod 2^16	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message
   * @param key
   * @return
   */
  private short calcAdditionMod216(short message, short key) {
	  short back;
	  back = (short) ((message + key) % Math.pow(2, 16));
	  
	  return back;
  }
  
  /**
   * Multiplikation in Z*_((2^16)+1)	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message
   * @param key
   * @return
   */
  private short calcMultiplikationZ(short message, short key) {
	  short back;
	  int b;
	  int m = message;
	  int k = key;
	  //Sonderfälle, wenn 0 eingegeben wird, ersetze durch 2^16
	  if (m==0) m=(int) Math.pow(2,16);
	  if (k==0) k=(int) Math.pow(2, 16);
	  //eigentliche Rechnung
	  int mod = (int) (Math.pow(2, 16) +1);
	  b = ((message * key) % mod);
	  //Sonderfall, wenn 2^16 heraus kommt, ersetze durch 0
	  if (b==Math.pow(2, 16)) b=0;
	  back= (short) b;
	  return back;
  }
  
  /**
   * Bitwise XOR mit Block	2x 64bit eingaben, 1x 64 bit ausgabe
   * @param message
   * @param key
   * @return
   */
  private short[] calcBitwiseXORBlock(short[] message, short[] key) {
	  if (message.length != 8 || key.length !=8){
		  System.out.println("XOR Blöcke haben die falsche Länge! Abbruch.");
		  System.exit(0);
	  }
	  short[] back = new short[key.length];
	  for (int i=0;i<back.length;i++)
		  back[i]=calcBitwiseXor(message[i],key[i]);
	  return back;
  }
  
  /**
   * Berechnet den ggT von a und b
   * @param a
   * @param b
   * @return
   */
  private int getGCD(int a, int b)
  {
	 int tmp;
	 if(a<b) {
		 tmp = a;
		 a = b;
		 b = tmp;
	 }
     while (b!=0){
    	 tmp=a%b;
    	 a=b;
    	 b=tmp;
     }
     return a;
  }
  
  /**
   * Reduzierte Menge der Reste modulo mod
   */
  private int[] getReducedRest(short mod) {
	  ArrayList<Integer> remainders = new ArrayList<Integer>();
	  
	  //Füge alle mit ggT(a,mod)==1 der Rückgabe hinzu
	  for(int i = 0; i < mod; i++) {
		  if(getGCD(i,mod)==1) {
			  remainders.add(i);
		  }
	  }
	  
	  //Erstelle Rückgabe aus der Liste
	  int[] back = new int[remainders.size()];
	  Iterator<Integer> it = remainders.iterator();
	  int i = 0;
	  while (it.hasNext()) {
		  back[i] = it.next();
		  i++;
	  }
	  
	  return back;
  }
 
}
