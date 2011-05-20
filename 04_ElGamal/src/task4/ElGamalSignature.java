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
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
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
	
	private BigInteger[] myKeyPublic_ = new BigInteger[3]; // P, G, Y
	private BigInteger[] myKeyPrivate_ = new BigInteger[3]; // P, G, X
	private BigInteger[] foeKey_ = new BigInteger[3]; // P, G, Y
	
	private BigInteger myP_;
	private BigInteger myG_;
	private BigInteger myX_;
	private BigInteger myY_;
	
	private BigInteger foeP_;
	private BigInteger foeG_;
	private BigInteger foeY_;
	
	private String myPathOwnPublic_;
	private String myPathOwnPrivate_;
	private String foePathPublic_;
	
	
  /**
   * Erzeugt/Setzt einen neuen Schlüssel (Algo 7.4)
   * 
   * Nutzt Algorithmus 7.4
   * Wenn bestehende Schlüssel genutzt werden sollen, werden jediglich die Pfade
   * zu den Public und Private Dateien abgespeichert.
   * Wenn ein neuer Schlüssel erzeugt wird, wird er im Ordner des Programms 
   * abgespeichert und sollte manuell an seinen richtigen Ort verschoben werden.
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

  /**
   * Liest den Schlüssel mit dem Reader <code>key</code>.
   * 
   * Liest die Pfadnamen der Schlüsseldateien aus und
   * danach werden die eigentlichen Schlüsseldateien ausgelesen und in
   * interne Variablen abgelegt.
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
	  // Algo 7.8 (1) Signiere Nachricht M
	  final BigInteger BIGINTTWO = new BigInteger("2"); // 2
	  final BigInteger BIGINTP1 = myP_.subtract(BigInteger.ONE); // P-1

	  // Hole eigenen Schlüssel in handliche Variablen
	  BigInteger myP = myP_;
	  BigInteger myG = myG_;
	  BigInteger myX = myX_;
	  BigInteger myY = myY_;
	  
	  if(TEST) {
		  myP = new BigInteger("2819");
		  myG = new BigInteger("2");
		  myX = new BigInteger("2260");
		  myY = new BigInteger("101");
	  }
	  System.out.println("    * Eigene Schlüsselwerte:");
	  System.out.println("      P = " + myP);
	  System.out.println("      G = " + myG);
	  System.out.println("      X = " + myX);
	  System.out.println("      Y = " + myY);
	  
	  // (1a) Zufälliges k in {1,...,p-2} mit ggt(k,p-1)=1 wählen
	  BigInteger lower = BigInteger.ONE;
	  BigInteger upper = myP.subtract(BIGINTTWO);
	  BigInteger myK;
	  boolean check = true;
	  do {
		  myK = BigIntegerUtil.randomBetween(lower, upper);
		  check = !(myK.gcd(BIGINTP1).equals(BigInteger.ONE));
	  } while (check);
	  if(TEST) { myK = new BigInteger("333"); }
	  if(DEBUG) System.out.println("DDD| myK=\t" + myK);
	  System.out.println("    * k zufällig gewählt");
	  
	  // (1b) Berechne r = g^k mod p
	  BigInteger myR;
	  myR = myG.modPow(myK, myP); // r = g^k mod p
	  if(DEBUG) {System.out.println("DDD| myR=\t" + myR);}
	  System.out.println("    * r berechnet");
	  
	  // (1c) Berechne k^(-1) mod (p-1)
	  BigInteger myKN = myK.modInverse(BIGINTP1); // k^(-1) mod (p-1)
	  if(DEBUG) {System.out.println("DDD| myKN=\t" + myKN);}
	  
	  int blocksize = calcBlocksize(myP);
	  BigInteger read = readClear(cleartext, blocksize);
	  boolean isBad = false;
	  boolean loopRead = (read != null);
	  if(loopRead==false) {
		  isBad = true;
	  }
	  while(loopRead) {
		  if(TEST) { read = new BigInteger("999"); }
		  // (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		  BigInteger myM = read.mod(myP);
		  
		  // (1e) Berechne s = (M-xr)k^(-1) mod (p-1)
		  BigInteger myS = myX_.multiply(myR); // x * r
		  myS = myM.subtract(myS); // M-xr
		  myS = myS.multiply(myKN); // (M-xr)*k^(-1) 
		  myS = myS.mod(BIGINTP1); // (M-xr)*k^(-1) mod p-1
		  if(DEBUG) {System.out.println("DDD| myS=\t" + myS);}
		  
		  // Modifikation: C = (r,s) zu C' = r + s*p geändert
		  BigInteger myC = myS.multiply(myP);
		  myC = myC.add(myR);
		  if(DEBUG) {System.out.println("DDD| myC=\t" + myC);}
		  
		  // (1f) Sende foe Klartext
		  // (1f) Sende foe Signatur (r,s)
		  writeCipher(ciphertext, myC);
		  
		  // Prüfe nächstes Zeichen und lese es
		  read = readClear(cleartext, blocksize);
		  loopRead = (read != null);
	  }
	  if(!isBad) {
		  System.out.println("    * Modifizierte Signatur C' berechnet");
		  System.out.println("    * Modifizierte Signatur C' gespeichert");
	  } else {
		  System.out.println("    * Datei konnte nicht gelesen werden");
	  }
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
	  // Algo 7.8 - (2) Prüfe Signatur (r,s) auf M
	  
	  // (2a) get authentischen Public Key (p,g,y), y=g^x mod p von foe
	  foePathPublic_ = enterFoePublic();
	  readSecretsFoe();
	  
	  // Blocksize für Klartext
	  int blocksize = calcBlocksize(foeP_);
	  
	  // Berechne Signaturen und Vergleiche abschnittsweise
	  BigInteger readCipher = readCipher(ciphertext);
	  BigInteger readClear = readClear(cleartext,blocksize);
	  boolean isBad = false;
	  boolean loopReadClear = (readClear != null);
	  boolean loopReadCipher = (readCipher != null);
	  if(TEST) { readClear = new BigInteger("999"); }
	  if(TEST) { readCipher = new BigInteger("454"); }
	  if(TEST) { foeP_ = new BigInteger("2819");}
	  // Zeige Schlüsselwerte
	  System.out.println("    * Fremde Schlüsselwerte:");
	  System.out.println("      P = " + foeP_);
	  System.out.println("      G = " + foeG_);
	  System.out.println("      Y = " + foeY_);
	  while(loopReadClear && loopReadCipher && !isBad) {
		  // Lese Cipher (modifizierte Signatur), C'=r+s*p
		  BigInteger foeC = readCipher; // C' = r + s*p
		  if(TEST) { foeC = new BigInteger("1280041"); }
		  if(DEBUG) {System.out.println("DDD| C=\t" + foeC);}
		  
		  // Lese Klartext
		  BigInteger foeM = readClear; 
		  // (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		  foeM = foeM.mod(foeP_); // M mod P
		  if(TEST) { foeM = new BigInteger("999"); }
		  
		  // Ermittle s = c mod p
		  BigInteger foeS = foeC.divideAndRemainder(foeP_)[0];
		  if(DEBUG) {System.out.println("DDD| s=\t" + foeS);}
		  // Ermittle r = c % p
		  BigInteger foeR = foeC.divideAndRemainder(foeP_)[1];
		  if(DEBUG) {System.out.println("DDD| r=\t" + foeR);}
		  
		  // (2b) Prüfe ob 1 <= r <= p-1; false: abbruch
		  boolean ifLess = (foeR.compareTo(BigInteger.ONE) == -1);
		  boolean ifMore = (foeR.compareTo(foeP_.subtract(BigInteger.ONE)) == 1);
		  if(ifLess || ifMore) {
			  isBad = true;
		  }
		  
		  // (2c) Berechne v1 = y^r r^s mod p (entfällt bei Modifkation?)
		  BigInteger foeV1 = foeY_.modPow(foeR,foeP_);
		  BigInteger h = foeR.modPow(foeS, foeP_);
		  foeV1 = foeV1.multiply(h);
		  foeV1 = foeV1.mod(foeP_);
		  
		  // (2c) Berechne v2 = g^M mod p
		  BigInteger foeV2 = foeG_.modPow(foeM, foeP_);
		  
		  if(DEBUG) {System.out.println("DDD| V1=\t" + foeV1);}
		  if(DEBUG) {System.out.println("DDD| V2=\t" + foeV2);}
		  if(!foeV2.equals(foeV1)) {
			  isBad = true;
		  }
		  
		  // Lese nächste Zeichen
		  readCipher = readCipher(ciphertext);
		  readClear = readClear(cleartext,blocksize);
		  loopReadCipher = (readCipher != null);
		  loopReadClear = (readClear != null);
	  }
	  
	  // (2d) Akzeptiere, wenn v1==v2
	  if(!isBad) {
		  System.out.println("    * Signatur akzeptiert");
	  } else {
		  System.out.println("    * Signatur abgelehnt");
	  }
  }

  /**
   * Schreibt den Schlüssel mit dem Writer <code>key</code>.
   * 
   * Es werden jediglich die Schlüsselpfade in die Datei geschrieben.
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
	  myP_ = myP;
	  myG_ = myG;
	  myY_ = myY;
	  
	  // Public Key als Array
	  myKeyPublic_ = new BigInteger[3];
	  myKeyPublic_[0] = myP;
	  myKeyPublic_[1] = myG;
	  myKeyPublic_[2] = myY;
	  
	  // Set private key (p,g,x)
	  //myP_ = myP;
	  //myG_ = myG;
	  myX_ = myX;
	  
	  // Privater Schlüssel als Array
	  myKeyPrivate_ = new BigInteger[3];
	  myKeyPrivate_[0] = myP;
	  myKeyPrivate_[1] = myG;
	  myKeyPrivate_[2] = myX;
  }
  
  
  /**
   * Definition 3.2
   * @param modulus
   * @return
   */
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
  
  
  private int calcBlocksize(BigInteger p) {
	  // bs = floor( (L_p - 1) / 8 )
	  int blockSize = p.bitLength() - 1;
	  blockSize = (int) Math.floor(blockSize / 8.0);

	  if(blockSize <= 2) { blockSize = 3; }
	  if(blockSize > 256) { blockSize = 255; }
	  
	  return blockSize;
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
  
  
  private String enterPathOwnPublic() {
	  
	  BufferedReader standardInput = launcher.openStandardInput();
	  boolean accepted = false;
	  
	  String msg = "    ! Bitte geben Sie den Pfad zum Public Key an: \n";
	  msg = msg +  "      > Leere Eingabe - Standardwert (key_testpublic.txt)";
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
	  msg = msg +  "      > Leere Eingabe - Standardwert (key_testprivate.txt)";
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
  
  
  private void readSecrets() {
	  try {
		  BufferedReader br;
		  
		  // Lese Public Key
		  File filePublic = new File(myPathOwnPublic_);
		  br = launcher.openFileForReading(filePublic);
		  myP_ = new BigInteger(br.readLine());
		  myG_ = new BigInteger(br.readLine());
		  myY_ = new BigInteger(br.readLine());
		  br.close();
		  
		  // Public Key als Array
		  myKeyPublic_[0] = myP_;
		  myKeyPublic_[1] = myG_;
		  myKeyPublic_[2] = myY_;
		  
		  System.out.println("    * Public Key eingelesen");
		  
		  // Lese Private Key
		  File filePrivate = new File(myPathOwnPrivate_);
		  br = launcher.openFileForReading(filePrivate);
		  myP_ = new BigInteger(br.readLine());
		  myG_ = new BigInteger(br.readLine());
		  myX_ = new BigInteger(br.readLine());
		  br.close();
		  
		  // Privater Schlüssel als Array
		  myKeyPrivate_[0] = myP_;
		  myKeyPrivate_[1] = myG_;
		  myKeyPrivate_[2] = myX_;
		  System.out.println("    * Private Key eingelesen");
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
  }
  
  
  private void readSecretsFoe() {
	  try {
		  BufferedReader br;
		  
		  // Lese Public Key
		  File filePublic = new File(foePathPublic_);
		  br = launcher.openFileForReading(filePublic);
		  foeP_ = new BigInteger(br.readLine());
		  foeG_ = new BigInteger(br.readLine());
		  foeY_ = new BigInteger(br.readLine());
		  br.close();
		  
		  // Variablen als Array
		  foeKey_[0] = foeP_;
		  foeKey_[1] = foeG_;
		  foeKey_[2] = foeY_;
		  
		  System.out.println("    * Fremden Public Key eingelesen");
	  } catch (IOException e) {
		  System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
		  e.printStackTrace();
		  System.exit(1);
	  }
  }
}
