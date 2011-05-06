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
	  //TODO setze IDEA um. macht da eine eigene Methode Sinn?
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
  
  //TODO Multiplikation in Z*_((2^16)+1)	2x 16bit eingaben, 1x 16 bit ausgabe
  private short calcMultiplikationZ(short message, short key) {
	  short back;
	  int mod = (int) (Math.pow(2, 16) +1);
	  back = (short) ((message * key) % mod);
	  
	  return 0;
  }
  
  //TODO bitwise XOR mit Block	2x 64bit eingaben, 1x 64 bit ausgabe
  private short calcBitwiseXORBlock(short[] message, short[] key) {
	  return 0;
  }

}
