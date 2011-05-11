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
import java.math.BigInteger;
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
	
	//Konstante Rechenwerte
	final BigInteger MOD_2 = new BigInteger("2");
	final BigInteger MOD_216_ = new BigInteger("" + MOD_2.pow(16)); //Mod 2^16
	final BigInteger MOD_MULT_Z_= new BigInteger("" + MOD_216_.add(BigInteger.ONE)); //Mod 2^16+1
	
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
	  
	  //TODO lese IV ein (momentan Hardcoded)
	  String iv = "ddc3a8f6c66286d2"; //Hex
//	  BigInteger[] biIv = transformIv(iv);
	  
	  
	  //Lese Klartext ein (BigInteger[64bit][16bit])
	  BigInteger[][] vM = getClear(cleartext);
	  
	  //Bereite Ciphertext vor
	  BigInteger[][] vC = new BigInteger[vM.length][4];

	  //CBC
	  short[][] keyExp = expandKey(ideaKey);
	  vC[0] = transformIv(iv); //Setze c[0] = iv, iv 64 bit lang
//	  System.out.println("### " + vM.length + "\t" + vC.length);
	  for(int i = 1; i < vM.length; i++) {
		  BigInteger[] xored = new BigInteger[4];
		  for(int j = 0; j < 4; j++) {
			  //FIXME NullPointerException, weil vC[i-1][j] null ist (noch nicht gesetzt)
//			  System.out.println(vM[i][j] + "\t" + i + "\t" + j + "\t" + vC[i-1][j]);
			  xored[j] = calcBitwiseXor(vM[i][j], vC[i-1][j]); //M_i XOR C_(i-1)
		  }
		  //TODO keyExp muss BigInteger sein! erst dann wird doIDEA freigegeben
//		  vC[i-1] = doIDEA(xored, keyExp);
	  }
	  
	  //TODO Ausgabe Ciphertext / Was nu mit vC? Irgendwohin ausgeben.
	  //Speicher Ciphertext
	  try{
		  for(int i = 0; i < vC.length; i++) {
			  for(int j = 0; j < vC[i].length;j++) {
				  BigInteger write = new BigInteger(vC[i][j].toString(2) + "00000100",2);
				  writeCipher(ciphertext, write);
				  //ciphertext.write(vC[i][j]);
			  }
		  }
		  ciphertext.close();
	  } catch(IOException e) {
		  System.err.println("!!Tja. Error.");
	  }
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
  private BigInteger calcBitwiseXor(BigInteger message1, BigInteger message2) {
	  BigInteger back;
	  back = message1.xor(message2);
	  
	  return back;
  }
  
  /**
   * Addition mod 2^16	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message1
   * @param message2
   * @return
   */
  private BigInteger calcAdditionMod216(BigInteger message1, BigInteger message2) {
	  BigInteger back;
	  //(m1 + m2) % 2^16
	  back = message1.add(message2);
	  back = back.mod(MOD_216_);
	  
	  return back;
  }
  
  /**
   * Multiplikation in Z*_((2^16)+1)	2x 16bit eingaben, 1x 16 bit ausgabe
   * @param message1
   * @param message2
   * @return
   */
  private BigInteger calcMultiplikationZ(BigInteger message1, BigInteger message2) {
	  //Sonderfälle, wenn 0 eingegeben wird, ersetze durch 2^16
	  if (message1.equals(BigInteger.ZERO)) {
		  message1 = new BigInteger(""+ Math.pow(2,16));
	  }
	  if (message2.equals(BigInteger.ZERO)) {
		  message2 = new BigInteger(""+ Math.pow(2,16));
	  }
	  //eigentliche Rechnung m1*m2 mod 2^16+1
	  BigInteger back; //return value
	  back = message1.multiply(message2);
	  back = back.mod(MOD_MULT_Z_);
	  
	  //Sonderfall, wenn 2^16 heraus kommt, ersetze durch 0
	  if (back.equals(MOD_216_)) back=BigInteger.ZERO;
	  return back;
  }
  
  /**
   * Bitwise XOR mit Block	2x 64bit eingaben, 1x 64 bit ausgabe
   * @param message
   * @param key
   * @return
   */
  private BigInteger[] calcBitwiseXORBlock(BigInteger[] message, BigInteger[] key) {
	  if (message.length != 8 || key.length !=8){
		  System.out.println("XOR Blöcke haben die falsche Länge! Abbruch.");
		  System.exit(0);
	  }
	  BigInteger[] back = new BigInteger[key.length];
	  for (int i=0;i<back.length;i++)
		  back[i]=calcBitwiseXor(message[i],key[i]);
	  return back;
  }
  
  /**
   * Umsetzung des IDEA
   */
  private BigInteger[] doIDEA(BigInteger[] m,BigInteger[][] k) {
	  BigInteger[][] vK = new BigInteger[9][6]; //Temporär, Parameterübergabe
	  BigInteger[][] vT = new BigInteger[5][4]; //Zwischenwerte des Algorithmus'
	  BigInteger[] vZ = new BigInteger[4]; //Zwischenwerte der Nachrichten
	  BigInteger[] vC = new BigInteger[4]; //Rückgabe
	  
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
		  vT[0][0] = calcMultiplikationZ(vZ[0], vK[r][0]);	//Z1 MultZ K1[r]  	> T11
		  vT[0][1] = calcAdditionMod216(vZ[1], vK[r][1]);	//Z2 Add216 K2[r] 	> T12
		  vT[0][2] = calcAdditionMod216(vZ[2], vK[r][2]);	//Z3 Add216 K3[r] 	> T13
		  vT[0][3] = calcMultiplikationZ(vZ[3], vK[r][3]);	//Z4 MultZ K4[r]  	> T14
		  
		  vT[1][0] = calcBitwiseXor(vT[0][0], vT[0][2]);	//T11 XOR T13 	> T21
		  vT[1][1] = calcBitwiseXor(vT[0][1], vT[0][3]);	//T12 XOR T14 	> T22
		  
		  vT[2][0] = calcMultiplikationZ(vT[1][0], vK[r][4]);	//T21 MultZ K5[r] 	> T31
		  vT[2][1] = calcAdditionMod216(vT[2][0], vT[1][1]);	//T31 Add216 T22  	> T32
		  vT[2][2] = calcMultiplikationZ(vT[2][1], vK[r][5]);	//T32 MultZ K6[r] 	> T33
		  vT[2][3] = calcAdditionMod216(vT[2][0], vT[2][3]);	//T31 Add216 T34  	> T34
		  
		  vT[3][0] = calcBitwiseXor(vT[0][0], vT[2][2]); //T11 XOR T33	> T41
		  vT[3][1] = calcBitwiseXor(vT[0][2], vT[2][2]); //T13 XOR T33	> T42
		  vT[3][2] = calcBitwiseXor(vT[0][1], vT[2][3]); //T12 XOR T34	> T43
		  vT[3][3] = calcBitwiseXor(vT[0][3], vT[2][3]); //T14 XOR T34	> T44

		  //Setze Zwischenwerte
		  vZ[0] = vT[3][0]; // Z1 = T41
		  vZ[1] = vT[3][2]; // Z2 = T43
		  vZ[2] = vT[3][1]; // Z3 = T42
		  vZ[3] = vT[3][3]; // Z4 = T44
	  }
	  
	  //Runde 9, Ausgabetransformation
	  vC[0] = calcMultiplikationZ(vZ[0], vK[8][0]);	//Z1 MultZ K1[9]	> T51
	  vC[1] = calcAdditionMod216(vZ[1], vK[8][1]);	//Z2 Add216 K2[9]	> T52
	  vC[2] = calcAdditionMod216(vZ[2], vK[8][2]);	//Z3 Add216 K3[9]	> T53
	  vC[3] = calcMultiplikationZ(vZ[3], vK[8][3]);	//Z4 MultZ K4[9]	> T54
	  
	  //Rückgabe
	  return vC;
  }

  private short[][] reverseKey(short[][] key) {
	  short[][] vR = key.clone();
	  short mod = (short) (Math.pow(2,16));
	  short mod1 = (short) (mod + 1);
	  
	  //Schlüssel der Runden 1-9
	  for(int r = 0; r < 9; r++) {
		  //TODO wieder freigeben und Fehler entfernen
//		  vR[r][0] = calcModInv(key[10-r-1][0],mod1);	//K1'=(K1^(10-r)) ^ (-1)
//		  vR[r][1] = calcModNeg(key[10-r-1][1],mod);	//K2'=-(K2^(10-r))
//		  vR[r][2] = calcModNeg(key[10-r-1][2], mod);	//K3'=-(K3^(10-r))
//		  vR[r][3] = calcModInv(key[10-r-1][3], mod1);	//K4'=(K4^(10-r)) ^ (-1)
		  
		  //Runde 2-8: Schlüssel K3 <-> K2 tauschen
		  if(r > 0 && r < 8) {
			  short tmp = vR[r][2];
			  vR[r][2] = vR[r][1];
			  vR[r][1] = tmp;
		  }
		  
		  //nur für Runde 1-8 Schlüssel 5 und 6
		  if(r < 8) {
			vR[r][4] = key[9-r-1][4];	//K5'=K5^(9-r)
			vR[r][5] = key[9-r-1][5];	//K6'=K6^(9-r)
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
  private BigInteger calcModInv(BigInteger a, BigInteger n) {
	  return a.modInverse(n);
//	  for (short x = 0; x < n; x++) {
//		  if(getGCD(x,n)==1 && (a * x) % n == 1) {
//			  return x;
//		  }
//	  }
//	  return -1;
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
	  
	  return back;
  }
  
  private ArrayList<Short> readInputStreamToList(FileInputStream fis) {
	  ArrayList<Short> back = new ArrayList<Short>();
	  try {
		  while(fis.available()>0) {
			  short c = (short) fis.read();
			  back.add(c);
		  }
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  
	  return back;
  }

  private BigInteger[][] getClear(FileInputStream cleartext) {
	  
	  //Lese Stream aus
	  ArrayList<BigInteger> list = new ArrayList<BigInteger>();
	  BigInteger read;
	  while((read = readClear(cleartext, 4)) != null) {
		  read = read.shiftRight(8); //Entfernt die Anzahl (immer 4)
		  list.add(read);
	  }
	  //Erweiter Liste auf Vielfaches von 4
	  if(list.size() % 4 != 0) {
		  int to = 4 - (list.size() % 4);
		  for(int i = 0; i < to; i++) {
			  list.add(BigInteger.ZERO);
		  }
	  }
	  
	  BigInteger[][] back = new BigInteger[list.size() / 4][4]; //return value
	  Iterator<BigInteger> it = list.iterator();
	  int counter = 0;
	  while (it.hasNext()) {
		  //Füge jeweils 16 bit in den Array
		  back[counter][0] = it.next();
		  back[counter][1] = it.next();
		  back[counter][2] = it.next();
		  back[counter][3] = it.next();
		  counter++;
	  }
	  
	  return back;
  }

  private BigInteger[] transformIv(String iv) {
	  BigInteger[] back = new BigInteger[4];
	  if(iv.length() != 16){
		  System.out.println("Fehler: Falsche Schlüssellänge! Abbruch.");
		  System.exit(1);
	  }
	  for(int i = 0; i < 4;i++) {
		  String sT = iv.substring(i*4, i*4+4);
		  back[i] = new BigInteger(sT, 16);
	  }
	  return back;
  }
  
  private BigInteger transformString(String string) {
	  String s = "";
	  BigInteger bigInteger;
	  char character;
	  for(int i = 0; i < string.length();i++) {
		  character = string.charAt(i);
		  bigInteger = new BigInteger(""+ (int)character);
		  s = s + fillZeros(bigInteger.toString(2), 8);
		  System.out.println("s: \t" + s);
	  }
	  
	  return new BigInteger(s,2);
  }
  
  /**
   * Ergänzt die Nullen für 8 Bit Darstellung
   * @param string	String mit binärer Zahlendarstellung
   * @return	gibt den mit Nullen erweiterten String zurück
   */
  private String fillZeros(String string,int length) {
	  while(string.length() % length != 0) {
		  string = "0" + string;
	  }
	  return string;
  }
}
