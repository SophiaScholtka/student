/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Fingerprint.java
 * Beschreibung: Dummy-Implementierung der Hash-Funktion von Chaum, van Heijst
 *               und Pfitzmann
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task5;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.HashFunction;

/**
 * Dummy-Klasse für die Hash-Funktion von Chaum, van Heijst und Pfitzmann.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:20:18 CEST 2010
 */
public final class Fingerprint extends HashFunction {

private final boolean DEBUG = true;
	
	private BigInteger myP_;
	private BigInteger myG1_;
	private BigInteger myG2_;
	
  /**
   * Berechnet den Hash-Wert des durch den FileInputStream
   * <code>cleartext</code> gegebenen Klartextes und schreibt das Ergebnis in
   * den FileOutputStream <code>ciphertext</code>.
   * 
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   * Der FileOutputStream, in den der Hash-Wert geschrieben werden soll.
   */
  public void hash(FileInputStream cleartext, FileOutputStream ciphertext) {
	  try {
		  
		  //TODO Param einlesen
		  //BigInteger myP_ = new BigInteger("2999",10);
		  //BigInteger myG1_ = new BigInteger("17",10);
		  //BigInteger myG2_ = new BigInteger("1235",10);
		  int Lp=myP_.bitLength();
		  BigInteger read,write,temp1,temp2;
		  byte m1[] = new byte[(Lp-2)/8]; //soviele byte kann man mit der Primzahl p verarbeiten.
		  byte m2[] = new byte[(Lp-2)/8];
		  int m1laenge, m2laenge;
		  m1laenge = cleartext.read(m1);
		  m2laenge = cleartext.read(m2);
		  if (DEBUG) System.out.println(">>>m1l und m2l "+m1laenge +" "+m2laenge);
		  while(m1 != null){
			  temp1=new BigInteger(m1);
			  if (m2 == null) {
				  temp2= new BigInteger("0");
			  } else {
				  temp2=new BigInteger(m2);
			  }
			  if (DEBUG) System.out.println(">>>temp1 is "+temp1);
			  if (DEBUG) System.out.println(">>>temp2 is "+temp2);
			  temp1=myG1_.modPow(temp1, myP_);
			  temp2=myG2_.modPow(temp2, myP_);
			  write=(temp1.multiply(temp2)).mod(myP_);
			  if (DEBUG) System.out.println(">>>write is "+write);
			  cleartext.read(m1);
			  cleartext.read(m2);
			  break;
		  }
	  } catch (IOException e){
		  System.err.println(e);
	  }
  }

  /**
   * Erzeugt neue Parameter.
   * 
   * @see #readParam readParam
   * @see #writeParam writeParam
   */
  public void makeParam() {
	  // Erzeuge Parameter p,g1,g2
	  int bitLength = enterBitLength();
	  
	  // erzeuge sichere Primzahl p, min 512 bits
	  Random random = new Random();
	  boolean isPrime = false;
	  BigInteger p = BigIntegerUtil.TWO;
	  BigInteger q = BigIntegerUtil.TWO;
	  do {
		  q = BigInteger.probablePrime(bitLength-1, random);
		  p = q.multiply(BigIntegerUtil.TWO);
		  p = p.add(BigInteger.ONE);
		  
		  isPrime = p.isProbablePrime(99);
	  } while (!isPrime);
	  
	  // erzeuge g1,g2 primitive Wurzeln mod p
	  BigInteger g1, g2;
	  boolean checkEqRoot = true;
	  do {
		  g1 = calcPrimeRoot(p, q);
		  g2 = calcPrimeRoot(p, q);
		  
		  checkEqRoot = g1.equals(g2);
	  } while (checkEqRoot);
	  
	  // Setze globale Variablen
	  myP_ = p;
	  myG1_ = g1;
	  myG2_ = g2;
  }

  /**
   * Liest die Parameter mit dem Reader <code>param</code>.
   * 
   * @param param
   * Der Reader, der aus der Parameterdatei liest.
   * @see #makeParam makeParam
   * @see #writeParam writeParam
   */
  public void readParam(BufferedReader param) {
	  
	  try {
		  // Hole Pfade der Paramdatei
		  myP_ = new BigInteger(param.readLine());
		  myG1_ = new BigInteger(param.readLine());
		  myG2_ = new BigInteger(param.readLine());
		  
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  
  }

  /**
   * Berechnet den Hash-Wert des durch den FileInputStream
   * <code>cleartext</code> gegebenen Klartextes und vergleicht das
   * Ergebnis mit dem durch den FileInputStream <code>ciphertext</code>
   * gelieferten Wert.
   *
   * @param ciphertext
   * Der FileInputStream, der den zu prüfenden Hash-Wert liefert.
   * @param cleartext
   * Der FileInputStream, der den Klartext liefert, dessen Hash-Wert berechnet
   * werden soll.
   */
  public void verify(FileInputStream ciphertext, FileInputStream cleartext) {

  }
  
  
  
  
  /**
   * Schreibt die Parameter mit dem Writer <code>param</code>.
   * 
   * @param param
   * Der Writer, der in die Parameterdatei schreibt.
   * @see #makeParam makeParam
   * @see #readParam readParam
   */
  public void writeParam(BufferedWriter param) {
	  
	  // Schreibe Pfade
	  try {
		  param.write("" + myP_);
		  param.newLine();
		  param.write("" + myG1_);
		  param.newLine();
		  param.write("" + myG2_);
		  param.close();
	  } catch (IOException e) {
		  e.printStackTrace();
	  }
	  System.out.println("    * Schlüsseldatei gespeichert");
	  
  }
  
  
  
  

  /**
   * Algo 7.3
   * @param bitLength
   * @return
   */
  private BigInteger calcPrimeRoot(BigInteger p, BigInteger q) {
	  
	  // Generiere primitive Wurzel g in Z_p^*
	  boolean checkRoot = false;
	  BigInteger g = BigIntegerUtil.TWO;
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
	  return g;
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
					  System.out.println(msg);
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
}
