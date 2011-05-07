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
  
  private short[] hexIVtoShortBlock(String iv){
	  short[] block = new short[4];
	  if (iv.length()<16){
		  System.out.println("Initialisierungsvektor ist zu kurz! Abbruch.");
		  System.exit(0);
	  }
	  try {
		  //TODO 16 Zeichen hex-string in 4 shorts umrechnen
	  } catch (NumberFormatException e){
		  System.out.println("Fehler beim Parsen des IV! Abbruch.");
		  System.exit(0);
	  }
	  return block;
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
	  
	  //CBC
	  //TODO CBC: Umrechnung der Strings in shorts
	  //FIXME CBC: Muss ingesamt später angepasst werden, gerade Variablen
	  String iv = "ddc3a8f6c66286d2";
	  String sClear = "abcdefghijklmnopqrstuvwxyz";
	  short[][] vM = new short[1][4]; //n-Bit Klartextblöcke M1...Mt
	  short[][] vC = new short[vM.length][4];
	  
	  short[][] keyExp = expandKey(ideaKey);
	  vC[0] = stringKeytoShortKey(iv); //Setze c[0] = iv, iv 64 bit lang
	  for(int i = 1; i < vM.length; i++) {
		  short[] xored = new short[4];
		  for(int j = 0; j < 4; j++) {
			  xored[j] = calcBitwiseXor(vM[i][j], vC[i-1][j]); //M_i XOR C_(i-1)
		  }
		  vC[i-1] = doIDEA(xored, keyExp);
	  }
	  
	  //Was nu mit vC? Irgendwohin ausgeben.
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
	  vC[1] = calcMultiplikationZ(vZ[1], vK[8][1]);	//Z1 MultZ K1[9]	> T51
	  vC[2] = calcAdditionMod216(vZ[2], vK[8][2]);	//Z2 Add216 K2[9]	> T52
	  vC[3] = calcAdditionMod216(vZ[3], vK[8][3]);	//Z3 Add216 K3[9]	> T53
	  vC[4] = calcMultiplikationZ(vZ[4], vK[8][4]);	//Z4 MultZ K4[9]	> T54
	  
	  //Rückgabe
	  return vC;
  }

  private short[][] reverseKey(short[][] key) {
	  short[][] vR = key.clone();
	  short mod = (short) (Math.pow(2,16));
	  short mod1 = (short) (mod + 1);
	  
	  //Schlüssel der Runden 1-9
	  for(int r = 0; r < 9; r++) {
		  vR[r][1] = calcModInv(key[10-r-1][1],mod1);	//K1'=(K1^(10-r)) ^ (-1)
		  vR[r][2] = calcModNeg(key[10-r-1][2],mod);	//K2'=-(K2^(10-r))
		  vR[r][3] = calcModNeg(key[10-r-1][3], mod);	//K3'=-(K3^(10-r))
		  vR[r][4] = calcModInv(key[10-r-1][4], mod1);	//K4'=(K4^(10-r)) ^ (-1)
		  
		  //Runde 2-8: Schlüssel K3 <-> K2 tauschen
		  if(r > 0 && r < 8) {
			  short tmp = vR[r][3];
			  vR[r][3] = vR[r][2];
			  vR[r][2] = tmp;
		  }
		  
		  //nur für Runde 1-8 Schlüssel 5 und 6
		  if(r < 8) {
			vR[r][5] = key[9-r-1][5];	//K5'=K5^(9-r)
			vR[r][6] = key[9-r-1][6];	//K6'=K6^(9-r)
		  }
	  }
	  
	  return vR;
  }
  
  /**
   * Berechnet die modulare Invese x für x = a^ (-1) mod n
   * @param a
   * @param n
   * @return
   */
  private short calcModInv(short a, short n) {
	  for (short x = 0; x < n; x++) {
		  if(getGCD(x,n)==1 && (a * x) % n == 1) {
			  return x;
		  }
	  }
	  return -1;
  }
  
  /**
   * Berechnet -x = (n - a) mod n
   * @param a
   * @param n
   * @return
   */
  private short calcModNeg(short a, short n) {
	  return (short) ((n - a) % n);
  }
  
  private int getGCD(int a, int b) {
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
  
  
  private short[] makeStringToShort(String string) {
	  short[] back = new short[string.length()];
	  
	  for(int i = 0; i< string.length();i++) {
		  char c = string.charAt(i);
		  back[i] = (short)c;
	  }
	  
	  return null;
  }
  
}
