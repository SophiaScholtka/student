package chiffre;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

public class RSA extends BlockCipher {

	@Override
	public void decipher(FileInputStream arg0, FileOutputStream arg1) {

	}

	@Override
	public void encipher(FileInputStream arg0, FileOutputStream arg1) {

	}

	@Override
	public void makeKey() {

	}

	@Override
	public void readKey(BufferedReader arg0) {

	}

	@Override
	public void writeKey(BufferedWriter arg0) {

	}

	/**
	 * Schlüsselerzeugung für das RSA, Algo 5.3
	 * 
	 * @param bitLength
	 * @return Array mit {n,e,d}, wobei Public Key (n,e) und Private Key d
	 */
	public static final BigInteger[] generateKey(int bitLength) {
		BigInteger p; // Primzahl p
		BigInteger q; // Primzahl q
		
		// (1) Erzeuge zwei gleich große Primzahlen p,q ungefähr gleicher Länge
		boolean isPrime = false;
		Random random = new Random();
		do {
			p = BigInteger.probablePrime(bitLength - 1, random);
			q = BigInteger.probablePrime(bitLength - 1, random);
			
			isPrime = p.isProbablePrime(50) && q.isProbablePrime(50); 
		} while (!isPrime);
		
		// (2)a Berechne n = pq
		BigInteger n= p.multiply(q); 
		// (2)b Berechne phi(n) = (p-1)(q-1)
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		// (3) wähle e, 1 < e < phi(n), ggT(e,phi(n) = 1
		boolean ok = false;
		BigInteger e;
		do {
			e = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, phi);
			
			ok = (e.gcd(phi).equals(BigInteger.ONE));
		} while (!ok);
		
		// (4) d = e^-1 mod phi (mit Algo 3.3)
		BigInteger d = e.modInverse(phi);
		
		// (5) Public Key (n,e) und Private Key d
		BigInteger[] rsaKeys = new BigInteger[3];
		rsaKeys[0] = n; // Public n
		rsaKeys[1] = e; // Public e
		rsaKeys[2] = d; // Public d
		return rsaKeys;
	}
	
}
