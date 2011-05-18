/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalSignature.java
 * Beschreibung: Dummy-Implementierung des ElGamal-Public-Key-Signaturverfahrens
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;
import de.tubs.cs.iti.jcrypt.chiffre.Signature;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Signaturverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:14:47 CEST 2010
 */
public final class ElGamalSignature extends Signature {
	
	private final boolean DEBUG = false;
	private final boolean TEST = false;
	
	private BigInteger[] myKeyPublic_; // P, G, Y
	private BigInteger[] myKeyPrivate_; // P, G, X
	private BigInteger[] foeKey_;
	
	private String myPathOwnPublic_;
	private String myPathOwnPrivate_;
	
	
  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * Nutzt Algorithmus 7.4
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
	  
	  // Hole Pfade der Key Dateien
	  try {
		  myPathOwnPublic_ = key.readLine();
		  myPathOwnPrivate_ = key.readLine();
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  
	  
	  // Lese Public Key
	  // TODO Lese Public Key
	  
	  // Lese Private Key
	  // TODO Lese Private Key
  }

  /**
   * Signiert den durch den FileInputStream <code>cleartext</code> gegebenen
   * Klartext und schreibt die Signatur in den FileOutputStream
   * <code>ciphertext</code>.
   * <p>Das blockweise Lesen des Klartextes soll mit der Methode {@link
   * #readClear readClear} durchgeführt werden, das blockweise Schreiben der
   * Signatur mit der Methode {@link #writeCipher writeCipher}.</p>
   * 
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   * Der FileOutputStream, in den die Signatur geschrieben werden soll.
   */
  public void sign(FileInputStream cleartext, FileOutputStream ciphertext) {

  }

  /**
   * Überprüft die durch den FileInputStream <code>ciphertext</code> gegebene
   * Signatur auf den vom FileInputStream <code>cleartext</code> gelieferten
   * Klartext.
   * <p>Das blockweise Lesen der Signatur soll mit der Methode {@link
   * #readCipher readCipher} durchgeführt werden, das blockweise Lesen des
   * Klartextes mit der Methode {@link #readClear readClear}.</p>
   *
   * @param ciphertext
   * Der FileInputStream, der die zu prüfende Signatur liefert.
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert, auf den die Signatur
   * überprüft werden soll.
   */
  public void verify(FileInputStream ciphertext, FileInputStream cleartext) {

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
	  
	  // Schreibe Schlüsseldateien
	  try{
		  BufferedWriter keys;
		  
		  // Schreibe Public
		  File filePublic = new File(myPathOwnPublic_);
		  if(!filePublic.exists()) {
			  filePublic.createNewFile();
		  }
		  keys = launcher.openFileForWriting(filePublic);
		  for(int i = 0; i < myKeyPublic_.length; i++) {
			  keys.write("" + myKeyPublic_[i]);
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
		  for(int i = 0; i < myKeyPrivate_.length; i++) {
			  keys.write("" + myKeyPrivate_[i]);
			  keys.newLine();
		  }
		  keys.close();
		  System.out.println("    * Private Key gespeichert");
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
	  
	
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
	  // (2) berechnet y = g^x mod p (Alg. 3.1) TODO Fast Exp 3.1?
	  BigInteger myY = myG.modPow(myX, myP); // Sets Y bwz. G^X
	  System.out.println("    * Y erzeugt");
	  if(DEBUG) { System.out.println("DDD| myX = " + myX.toString()); }
	  if(DEBUG) { System.out.println("DDD| myY = " + myY.toString()); }
	  
	  // Set public key (p,g,y)
	  myKeyPublic_ = new BigInteger[3];
	  myKeyPublic_[0] = myP;
	  myKeyPublic_[1] = myG;
	  myKeyPublic_[2] = myY;
	  // Set private key (p,g,x)
	  myKeyPrivate_ = new BigInteger[3];
	  myKeyPrivate_[0] = myP;
	  myKeyPrivate_[1] = myG;
	  myKeyPrivate_[2] = myX;
  }
  
  
  
  
  /**
   * Algo 7.3
   * @param bitLength
   * @return
   */
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
	  } while (isPrime);
	  
	  
	  // Generiere primitive Wurzel g in Z_p^*
	  boolean checkRoot = false;
	  BigInteger g = new BigInteger("2");
	  BigInteger biNeg1 = new BigInteger("-1");
	  biNeg1 = biNeg1.mod(p);
	  do {
		  g = calcReducedRest(p);
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
  /**
   * Definition 3.2
   * @param modulus
   * @return
   */
  private BigInteger calcReducedRest(BigInteger modulus) {
	  	  
	  BigInteger reducedRest = BigInteger.ZERO; // Rückgabe
	  Random randomGenerator = new Random();
	  boolean check = false;
	  while (!check) {
		  reducedRest = BigIntegerUtil.randomSmallerThan(modulus,randomGenerator);
		  
		  check = reducedRest.gcd(modulus).equals(BigInteger.ONE);
	  }
	  	  
	  return reducedRest;
	  
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
  
  

  private boolean enterWriteNew() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Wollen Sie einen bestehenden Schlüssel überschreiben? [Y/N]";
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
	  msg = msg +  "      > Leere Eingabe - Standardwert";
	  System.out.println(msg);
	  String path = ""; // Rückgabe
	  do {
		  msg = "    ! Bitte geben Sie den Pfad zum Public Key an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
//				  sIn = "../ElGamal/schluessel/us.auth.public";
				  sIn = "key_public.txt";
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
	  msg = msg +  "      > Leere Eingabe - Standardwert";
	  System.out.println(msg);
	  String path = ""; // Rückgabe
	  do {
		  msg = "    ! Bitte geben Sie den Pfad zum Private Key an.";
		  System.out.print("      ");
		  try {
			  String sIn = standardInput.readLine();
			  if (sIn.length() == 0 || sIn == null) {
				  sIn = "key_private.txt"; //
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
}
