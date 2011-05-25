/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalCipher.java
 * Beschreibung: Dummy-Implementierung der ElGamal-Public-Key-Verschlüsselung
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Verschlüsselungsverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:06:35 CEST 2010
 */
public final class ElGamalCipher extends BlockCipher {

	final boolean DEBUG = false;
	private BigInteger prikey;
	private BigInteger[] pubkey = new BigInteger[3];
	private BigInteger[] foekey = new BigInteger[3];
	private String myPathOwnPublic_;
	private String myPathOwnPrivate_;
	private String foePathPublic_;
	
	
  /**
   * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
   * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
   * <code>cleartext</code>.
   * <p>Das blockweise Lesen des Chiffretextes soll mit der Methode {@link
   * #readCipher readCipher} durchgeführt werden, das blockweise Schreiben des
   * Klartextes mit der Methode {@link #writeClear writeClear}.</p>
   *
   * @param ciphertext
   * Der FileInputStream, der den Chiffretext liefert.
   * @param cleartext
   * Der FileOutputStream, in den der Klartext geschrieben werden soll.
   */
  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
	  BigInteger read, read1, read2;
	  BigInteger z;
	  BigInteger write;
	  while(((read=readCipher(ciphertext)) != null)){
		  read1=read.mod(pubkey[0]);
		  read2=read.divide(pubkey[0]);
		  if (DEBUG) System.out.println(">>>In while, read1 is "+read1.toString()+ " read2 is "+ read2.toString());
		  z = (read1.modPow(prikey,pubkey[0])).modInverse(pubkey[0]);
		  write = z.multiply(read2).mod(pubkey[0]);
		  if (DEBUG) System.out.println(">>>In while, write is "+write.toString());
		  writeClear(cleartext,write);
	  }
  }

  /**
   * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
   * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
   * <code>ciphertext</code>.
   * <p>Das blockweise Lesen des Klartextes soll mit der Methode {@link
   * #readClear readClear} durchgeführt werden, das blockweise Schreiben des
   * Chiffretextes mit der Methode {@link #writeCipher writeCipher}.</p>
   * 
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   * Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
   */
  
  //TODO encipher und decipher noch mal checken
  public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {
	  //frage nach pubkey des Kommunikationspartners
	  foePathPublic_ = enterFoePublic();
	  readSecretsFoe();
	  int L = (foekey[0].bitLength()-1)/8;
	  L = Math.min(Math.max(3, L),2048);
	  if (DEBUG) System.out.println(">>>L is "+L);
	  BigInteger read;
	  BigInteger writea, writeb;
	  BigInteger k;
	  Random krand = new Random();
	  //solange es noch Klartext gibt
	  read = readClear(cleartext,L);
	  while(read !=null){
		  k = new BigInteger(foekey[0].bitLength()-1,krand);
		  //k = new BigInteger("999",10);
		  if(DEBUG) System.out.println(">>>read is "+read.toString());
		  writea = foekey[1].modPow(k, foekey[0]);
		  if(DEBUG) System.out.println(">>>writea "+writea.toString());
		  writeb = (read.multiply(foekey[2].modPow(k,foekey[0]))).mod(foekey[0]);
		  if(DEBUG) System.out.println(">>>writeb "+writeb.toString());
		  writeCipher(ciphertext,writea.add(writeb.multiply(foekey[0])));
		  read = readClear(cleartext,L);
	  }
  }
  
  private String enterFoePublic() {
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Bitte geben Sie den Pfad zum Public Key des anderen an: \n";
	  msg = msg +  "      > Leere Eingabe - Standardwert (key-testpublicfoe.txt)";
	  System.out.println(msg);
	  String path = ""; // Rückgabe
	  do {
		  msg = "    ! Bitte geben Sie den Pfad zum Public Key des anderen an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
				  sIn = "key-testpublicfoe.txt"; //
			  }
			  File file = new File(sIn);
			  if (file.exists() == true) {
				  path = sIn;
				  accepted = true;
			  } else {
				  System.out.println(msg);
				  accepted = false;
			  }
		  } catch (IOException e) {
			  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
			  e.printStackTrace();
			  System.exit(1);
		  }
	  } while (!accepted);
	  
	  return path;
  }

  private void readSecretsFoe() {
	  try {
		  BufferedReader br;
		  
		  // Lese Public Key
		  File filePublic = new File(foePathPublic_);
		  br = launcher.openFileForReading(filePublic);
		  foekey[0] = new BigInteger(br.readLine());
		  if (DEBUG) System.out.println(">>>FoeKey0 = "+foekey[0].toString());
		  foekey[1] = new BigInteger(br.readLine());
		  if (DEBUG) System.out.println(">>>FoeKey1 = "+foekey[1].toString());
		  foekey[2] = new BigInteger(br.readLine());
		  if (DEBUG) System.out.println(">>>FoeKey2 = "+foekey[2].toString());
		  br.close();
		  System.out.println("    * Fremden Public Key eingelesen");
		  
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
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
	  
	  boolean isOwnKey = enterWhichKey();
	  if(isOwnKey) { // Bestehende Schlüssel
		  System.out.println("    * Verwende bestehenden Schlüssel");
		  
		  myPathOwnPublic_ = enterPathOwnPublic();
		  System.out.println("    * Pfad (Public Key):  " + myPathOwnPublic_);
		  myPathOwnPrivate_ = enterPathOwnPrivate();
		  System.out.println("    * Pfad (Private Key): " + myPathOwnPrivate_);
		  
	  } else { // Neue Schlüssel
		  System.out.println("    * Generiere neuen Schlüssel");
		  
		  myPathOwnPublic_ = "key_public.txt";
		  myPathOwnPrivate_ = "key_private.txt";
		  generateKey();
		  writeSecrets();
	  }
	  
  }
  
  private boolean enterWhichKey() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Wollen Sie einen bestehenden Schlüssel verwenden? [Y/N]";
	  System.out.println(msg);
	  boolean back = false; // Rückgabe
	  do {
		  msg = "    ! Wollen sie einen bestehenden Schlüssel verwenden? [Y/N]";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
				  accepted = true;
				  back = true;
			  } else if (sIn.toLowerCase().equals("y")) {
				  accepted = true;
				  back = true;
			  } else if (sIn.toLowerCase().equals("n")) {
				  accepted = true;
				  back = false;
			  } else {
				  accepted = false;
			  }
		  } catch (IOException e) {
			  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
			  e.printStackTrace();
			  System.exit(1);
		  }
	  } while (!accepted);
	  
	  return back;
  }
  
  
  private String enterPathOwnPublic() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Bitte geben Sie den Pfad zum Public Key an: \n";
	  msg = msg +  "      > Leere Eingabe - Standardwert (key-testpublic.txt)";
	  System.out.println(msg);
	  String path = ""; // Rückgabe
	  do {
		  msg = "    ! Bitte geben Sie den Pfad zum Public Key an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
//				  sIn = "../ElGamal/schluessel/us.auth.public";
				  sIn = "key-testpublic.txt";
			  }
			  File file = new File(sIn);
			  if (file.exists() == true) {
				  path = sIn;
				  accepted = true;
			  } else {
				  System.out.println("      Datei existiert nicht.");
				  System.out.println(msg);
				  accepted = false;
			  }
		  } catch (IOException e) {
			  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
			  e.printStackTrace();
			  System.exit(1);
		  }
	  } while (!accepted);
	  
	  return path;
  }
  
  
  private String enterPathOwnPrivate() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Bitte geben Sie den Pfad zum Private Key an: \n";
	  msg = msg +  "      > Leere Eingabe - Standardwert (key-testprivate.txt)";
	  System.out.println(msg);
	  String path = ""; // Rückgabe
	  do {
		  msg = "    ! Bitte geben Sie den Pfad zum Private Key an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
				  sIn = "key-testprivate.txt"; //
			  }
			  File file = new File(sIn);
			  if (file.exists() == true) {
				  path = sIn;
				  accepted = true;
			  } else {
				  System.out.println(msg);
				  accepted = false;
			  }
		  } catch (IOException e) {
			  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
			  e.printStackTrace();
			  System.exit(1);
		  }
	  } while (!accepted);
	  
	  return path;
  }
  
  private void generateKey() {
	  
	  // (1) große sichere Primzahl p = 2q+1 mit q prim erzeugen
	  // (1) und primitive Wurzel g der mult. Gruppe Z_p^* erzeugen (Alg 7.3)
	  int bitLength = enterBitLength(); //min 512! 
	  System.out.println("    * Bitlänge = " + bitLength);
	  BigInteger[] keyAll = calcKeyAll(bitLength);
	  BigInteger myP = keyAll[0]; // Sets P
	  BigInteger myG = keyAll[1]; // Sets G
	  System.out.println("    * P erzeugt");
	  System.out.println("    * G erzeugt");
	  if(DEBUG) { System.out.println("DDD| myP bitLength=" + myP.bitLength()); }
	  if(DEBUG) { System.out.println("DDD| myP = " + myP.toString()); }
	  if(DEBUG) { System.out.println("DDD| myG = " + myG.toString()); }
	  
	  // (2) Alice wählt Zufallszahl x in {1,...,p-2}
	  BigInteger lower = BigInteger.ONE;
	  BigInteger upper = myP.subtract(new BigInteger("2"));
	  BigInteger myX = BigIntegerUtil.randomBetween(lower,upper); // Sets X
	  System.out.println("    * X erzeugt");
	  // (2) berechnet y = g^x mod p (Alg. 3.1) (Fast Exp 3.1 nicht verwendet)
	  BigInteger myY = myG.modPow(myX, myP); // Sets Y bwz. G^X
	  System.out.println("    * Y erzeugt");
	  if(DEBUG) { System.out.println("DDD| myX = " + myX.toString()); }
	  if(DEBUG) { System.out.println("DDD| myY = " + myY.toString()); }
	  
	  // Set public key (p,g,y)
	  pubkey[0] = myP;
	  pubkey[1] = myG;
	  pubkey[2] = myY;
	  
	  // Set private key (x)
	  prikey = myX;
  }
  
  private int enterBitLength() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;

	  String msg = "    ! Bitte geben sie die gewünschte Bitlänge für die Primzahl P an (minimum 512):";
	  System.out.println(msg);
	  int bitLength = 0; // Rückgabe
	  do {
		  msg = "    ! Bitte geben sie die Bitlänge an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if(sIn.length() == 0 || sIn == null) {
				  // Standardwert bei "keiner" Eingabe
				  bitLength = 512;
				  accepted = true;
			  } else {
				  bitLength = Integer.parseInt(sIn);
				  if(bitLength >= 512) {
					  accepted = true;
				  } else {
					  accepted = false;
				  }
			  }
		  } catch (IOException e) {
			  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
			  e.printStackTrace();
			  System.exit(1);
		  } catch (NumberFormatException e) {
			  System.err.println("      Keine gültige Zahl.");
			  System.out.println(msg);
		  }
	  } while (!accepted);
	  
	  return bitLength;
  }
  
  
  
  private BigInteger[] calcKeyAll(int bitLength) {
	  
	  // Generiere sichere Primzahl p
	  Random random = new Random();
	  boolean isPrime = false;
	  BigInteger p = new BigInteger("2");
	  BigInteger q = new BigInteger("2");
	  do {
		  q = BigInteger.probablePrime(bitLength-1, random);
		  p = q.multiply(new BigInteger("2"));
		  p = p.add(BigInteger.ONE);
		  
		  isPrime = p.isProbablePrime(99); // Prime zu %
	  } while (!isPrime);
	  
	  
	  // Generiere primitive Wurzel g in Z_p^*
	  boolean checkRoot = false;
	  BigInteger g = new BigInteger("2");
	  BigInteger biNeg1 = new BigInteger("-1");
	  biNeg1 = biNeg1.mod(p);
	  do {
		  g = generateReducedRest(p);
		  boolean isNotOne = !g.equals(BigInteger.ONE);
		  boolean isNotP1 = !g.equals(p.subtract(BigInteger.ONE));
		  if(isNotOne || isNotP1) {
			  BigInteger h;
			  h = g.modPow(q, p);
			  checkRoot = (h.equals(biNeg1));
		  } else {
			  checkRoot = false;
		  }
	  } while (checkRoot);
	  
	  // Setze Rückgabevariabel
	  BigInteger[] back = new BigInteger[2]; // Rückgabe
	  back[0] = p;
	  back[1] = g;
	  return back;
  }
  
  private BigInteger generateReducedRest(BigInteger modulus) {
  	  
	  BigInteger reducedRest = BigInteger.ZERO; // Rückgabe
	  Random randomGenerator = new Random();
	  boolean check = false;
	  while (!check) {
		  reducedRest = BigIntegerUtil.randomSmallerThan(modulus,randomGenerator);
		  
		  check = reducedRest.gcd(modulus).equals(BigInteger.ONE);
	  }
	  	  
	  return reducedRest;
	  
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
		  // Hole Pfade der Key Dateien
		  myPathOwnPublic_ = key.readLine();
		  myPathOwnPrivate_ = key.readLine();
		  
		  // Lese Public and Private Key
		  readSecrets();
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
	  // Schreibe Pfade
	  try {
		  key.write(myPathOwnPublic_);
		  key.newLine();
		  key.write(myPathOwnPrivate_);
		  key.close();
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  System.out.println("    * Schlüsseldatei gespeichert");
  }

  private void writeSecrets() {

	  // Schreibe Schlüsseldateien
	  try{
		  BufferedWriter keys;
		  
		  // Schreibe Public
		  File filePublic = new File(myPathOwnPublic_);
		  if(!filePublic.exists()) {
			  filePublic.createNewFile();
		  }
		  keys = launcher.openFileForWriting(filePublic);
		  for(int i = 0; i < pubkey.length; i++) {
			  keys.write("" + pubkey[i]);
			  keys.newLine();
		  }
		  keys.close();
		  System.out.println("    * Public Key gespeichert");
		
		  // Schreibe Private
		  File filePrivate = new File(myPathOwnPrivate_);
		  if(!filePrivate.exists()) {
			  filePrivate.createNewFile();
		  }
		  keys = launcher.openFileForWriting(filePrivate);
		  keys.write("" + pubkey[0]);
		  keys.newLine();
		  keys.write("" + pubkey[1]);
		  keys.newLine();
		  keys.write("" + prikey);
		  keys.newLine();
		  keys.close();
		  System.out.println("    * Private Key gespeichert");
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
}


	private void readSecrets() {
	  try {
		  BufferedReader br;
		  
		  // Lese Public Key
		  File filePublic = new File(myPathOwnPublic_);
		  br = launcher.openFileForReading(filePublic);
		  pubkey[0] = new BigInteger(br.readLine());
		  pubkey[1] = new BigInteger(br.readLine());
		  pubkey[2] = new BigInteger(br.readLine());
		  br.close();
		  System.out.println("    * Public Key eingelesen");
		  
		  // Lese Private Key
		  File filePrivate = new File(myPathOwnPrivate_);
		  br = launcher.openFileForReading(filePrivate);
		  //zwei nicht gebrauchte Zeilen "weglesen"
		  br.readLine();
		  br.readLine();
		  prikey = new BigInteger(br.readLine());
		  br.close();
		  System.out.println("    * Private Key eingelesen");
		  
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
	}
}