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
import java.math.BigInteger;

import de.tubs.cs.iti.jcrypt.chiffre.HashFunction;

/**
 * Dummy-Klasse für die Hash-Funktion von Chaum, van Heijst und Pfitzmann.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:20:18 CEST 2010
 */
public final class Fingerprint extends HashFunction {

	final boolean DEBUG = true;
	
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
	  //TODO Param einlesen
	  BigInteger myP_ = new BigInteger("2999",10);
	  BigInteger myG1_ = new BigInteger("17",10);
	  BigInteger myG2_ = new BigInteger("1235",10);
	  int Lp=myP_.bitLength();
	  BigInteger read, write,temp1,temp2;
	  read = new BigInteger("302924",10);
	  while(read != null){
		  temp1=read.mod(myP_);
		  temp2=read.divide(myP_);
		  temp1=myG1_.modPow(temp1, myP_);
		  temp2=myG2_.modPow(temp2, myP_);
		  write=(temp1.multiply(temp2)).mod(myP_);
		  if (DEBUG) System.out.println(">>>write is "+write);
		  //read = readClear(cleartext,(Lp-2)*2);
	  }
  }

  /**
   * Erzeugt neue Parameter.
   * 
   * @see #readParam readParam
   * @see #writeParam writeParam
   */
  public void makeParam() {

    System.out.println("Dummy für die Parametererzeugung.");
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

  }
}
