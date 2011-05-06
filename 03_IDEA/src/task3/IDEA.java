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
import java.util.ArrayList;
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
	  short[] Key = stringKeytoShortKey(originalKey);
	  //Schlüsselexpansion nach Algorithmus 4.1
	  short[] Keys = new short[52];
	  //Teile Key in acht 16-Bit-Teilschlüssel auf und weise diese direkt den ersten 8 Teilschlüsseln zu
	  for(int i=0;i<8;i++){
		  Keys[i]=(short) Key[i];
	  }
	  /* while noch nicht alle 52 teilschlüssel zugewiesen,
	   * führe auf Key einen zyklischen Linksshift um 25 Positionen durch,
	   * teile das Ergebnis in acht 16-Bit-Blöcke ein
	   * weise das Ergebnis den nächsten 8 (oder im letzten Schritt 4) Teilschlüsseln zu
	   */
	  
	  //Ich schreib es lieber nicht als while sondern als for-Schleife - Schlüssel 8 bis 47
	  for (int i=1;i<6;i++){
		  Key = shiftKey(Key);
		  for (int j=0;j<8;j++){
			  Keys[8*i+j]=Key[j];
		  }
	  }
	  //Schlüssel 48 bis 52
	  Key=shiftKey(Key);
	  for (int i=0;i<4;i++){
		  Keys[47+i]=Key[i];
	  }
	  //TODO fertigen Schlüssel Keys irgendwie sinnvoll abspeichern
  }

  private short[] shiftKey(short[] key) {
	  short[] back=key;
	// TODO key (Länge ist 8) zyklisch um 25 bits nach links verschieben und zurück geben
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
		//schreibe 2 Byte hintereinander in ein Short, indem das zweite mit 2^8 multipliziert wird
		back[i]=(short) (t1+ (int) Math.pow(2, 8)*t2);
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
  private short calcBitwiseXor(short message1, short message2) {
	  short back;
	  back = (short) (message1 ^ message2);
	  
	  return back;
  }
  
  /**
   * Addition mod 2^16	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message1
   * @param message2
   * @return
   */
  private short calcAdditionMod216(short message1, short message2) {
	  short back;
	  back = (short) ((message1 + message2) % Math.pow(2, 16));
	  
	  return back;
  }
  
  /**
   * Multiplikation in Z*_((2^16)+1)	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message1
   * @param message2
   * @return
   */
  private short calcMultiplikationZ(short message1, short message2) {
	  short back;
	  int b;
	  int m = message1;
	  int k = message2;
	  //Sonderfälle, wenn 0 eingegeben wird, ersetze durch 2^16
	  if (m==0) m=(int) Math.pow(2,16);
	  if (k==0) k=(int) Math.pow(2, 16);
	  //eigentliche Rechnung
	  int mod = (int) (Math.pow(2, 16) +1);
	  b = ((message1 * message2) % mod);
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
   * Umsetzung des IDEA
   */
  private short[] doIDEA(short[] m,short[][] k) {
	  short[][] vK = new short[9][6]; //Temporär, Parameterübergabe
	  short[][] vT = new short[5][4]; //Zwischenwerte des Algorithmus'
	  short[] vZ = new short[4]; //Zwischenwerte der Nachrichten
	  short[] vC = new short[4]; //Rückgabe
	  
	  //Prüfe Eingaben
	  if(m.length != 4 || k.length != 9) {
		  return null;
	  }
	  for (int i = 0; i < k.length; i++) {
		if(k[i].length != vK[i].length) {
			return null;
		}
	  }
	  vK = k;
	  
	  //Füge Nachricht als Startwerte der Zwischennachrichten ein.
	  for(int i = 0; i < vZ.length;i++) {
		  vZ[i] = m[i];
	  }
	  
	  //Runde r 1 bis 8
	  for(int r = 0; r < 8; r++) {
		  vT[1][1] = calcMultiplikationZ(vZ[1], vK[r][1]);	//Z1 MultZ K1[r]  	> T11
		  vT[1][2] = calcAdditionMod216(vZ[2], vK[r][2]);	//Z2 Add216 K2[r] 	> T12
		  vT[1][3] = calcAdditionMod216(vZ[3], vK[r][3]);	//Z3 Add216 K3[r] 	> T13
		  vT[1][4] = calcMultiplikationZ(vZ[4], vK[r][4]);	//Z4 MultZ K4[r]  	> T14
		  
		  vT[2][1] = calcBitwiseXor(vT[1][1], vT[1][3]);	//T11 XOR T13 	> T21
		  vT[2][2] = calcBitwiseXor(vT[1][2], vT[1][4]);	//T12 XOR T14 	> T22
		  
		  vT[3][1] = calcMultiplikationZ(vT[2][1], vK[r][5]);	//T21 MultZ K5[r] 	> T31
		  vT[3][2] = calcAdditionMod216(vT[3][1], vT[2][2]);	//T31 Add216 T22  	> T32
		  vT[3][3] = calcMultiplikationZ(vT[3][2], vK[r][6]);	//T32 MultZ K6[r] 	> T33
		  vT[3][4] = calcAdditionMod216(vT[3][1], vT[3][4]);	//T31 Add216 T34  	> T34
		  
		  vT[4][1] = calcBitwiseXor(vT[1][1], vT[3][3]); //T11 XOR T33	> T41
		  vT[4][2] = calcBitwiseXor(vT[1][3], vT[3][3]); //T13 XOR T33	> T42
		  vT[4][3] = calcBitwiseXor(vT[1][2], vT[3][4]); //T12 XOR T34	> T43
		  vT[4][4] = calcBitwiseXor(vT[1][4], vT[3][4]); //T14 XOR T34	> T44

		  //Setze Zwischenwerte
		  vZ[1] = vT[4][1]; // Z1 = T41
		  vZ[2] = vT[4][3]; // Z2 = T43
		  vZ[3] = vT[4][2]; // Z3 = T42
		  vZ[4] = vT[4][4]; // Z4 = T44
	  }
	  
	  //Runde 9, Ausgabetransformation
	  vC[1] = calcMultiplikationZ(vZ[1], vK[9][1]);	//Z1 MultZ K1[9]	> T51
	  vC[2] = calcAdditionMod216(vZ[2], vK[9][2]);	//Z2 Add216 K2[9]	> T52
	  vC[3] = calcAdditionMod216(vZ[3], vK[9][3]);	//Z3 Add216 K3[9]	> T53
	  vC[4] = calcMultiplikationZ(vZ[4], vK[9][4]);	//Z4 MultZ K4[9]	> T54
	  
	  //Rückgabe
	  return vC;
  }

}
