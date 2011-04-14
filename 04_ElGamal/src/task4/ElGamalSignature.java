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
import java.io.FileInputStream;
import java.io.FileOutputStream;

import de.tubs.cs.iti.jcrypt.chiffre.Signature;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Signaturverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:14:47 CEST 2010
 */
public final class ElGamalSignature extends Signature {

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {

    System.out.println("Dummy für die Schlüsselerzeugung.");
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

  }
}
