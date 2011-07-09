package task9;

import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public class PohligHellmann {
	
	// Schlüssel
	private BigInteger p_; // Große Primzahl
	private BigInteger e_; // Geheimer Schlüssel, Chiffrierschlüssel
	private BigInteger d_; // Öffentlicher Schlüssel, Dechiffrierschlüssel

	// Konstanten
	private final BigInteger ZERO_ = new BigInteger("0"); // 0
	private final BigInteger ONE_  = new BigInteger("1"); // 1
	private final BigInteger TWO_  = new BigInteger("2"); // 2
	private BigInteger PHI_P_;
	
	
	public PohligHellmann() {
	}

	/**
	 * Generiert eine Primzahl mit angegebener Bitlänge
	 * @param bitLength Bitlänge der Primzahl
	 * @return eine Primzahl
	 */
	public static BigInteger generatePrime(int bitLength) {
		return BigInteger.probablePrime(bitLength, new Random());
	}
	
	/**
	 * Schlüsselerzeugung für das Pohlig-Hellman-Verfahren; Algorithmus 5.1
	 * @param bitLength Bitlänge der Primzahl p
	 */
	public void makeKey(int bitLength) {
		// (1) Erzeuge große Primzahl p
		this.p_ = BigInteger.probablePrime(bitLength, new Random());
		this.PHI_P_ = p_.subtract(ONE_);

		computeKey(p_);
	}

	/**
	 * @see makeKey()
	 * @param p
	 *            große Primzahl p
	 */
	public void makeKey(BigInteger p) {
		this.p_ = p;
		computeKey(p);
	}

	/**
	 * @see makeKey(), makeKey(BigInteger p)
	 * @param p
	 *            große Primzahl
	 */
	private void computeKey(BigInteger p) {
		// (2) Wähle Chiffrierschlüssel e
		boolean isGGT1 = true;
		BigInteger e;
		do {
			// e \in setN mit 1<e<phi(p) = p-1 = 2<=e<phi(p)
			e = BigIntegerUtil.randomBetween(TWO_, PHI_P_, new Random());
			isGGT1 = (e.gcd(PHI_P_).equals(ONE_)); // ggT(e,p-1)=1
		} while (!isGGT1);
		this.e_ = e;
		
		// (3) Berechne Dechiffrierschlüssel d
		// d = e^-1 mod (p-1)
		BigInteger d = e.modInverse(PHI_P_);
		this.d_ = d;
		
		// (4)a Chiffrierschlüssel ist (p,e) (secret)
		// (4)b Dechiffrierschlüssel ist (p,d) (public)
	}
	
	
	public BigInteger getPrime() {
		return this.p_;
	}
	/**
	 * Ausgabe des Chiffrierschlüssels (p,e)
	 * @return (p,e) Chiffrierschlüssel
	 */
	public BigInteger[] getChipherKey() {
		BigInteger[] publicKey = new BigInteger[2];
		publicKey[0] = this.p_;
		publicKey[1] = this.e_;
		
		return publicKey;
	}
	
	/**
	 * Ausgabe des Dechiffrierschlüssels (p,d)
	 * @return (p,d) Dechiffrierschlüssel
	 */
	public BigInteger[] getDecipherKey() {
		BigInteger[] privateKey = new BigInteger[2];
		privateKey[0] = this.p_;
		privateKey[1] = this.d_;
		
		return privateKey;
	}
	
	/**
	 * Verschlüsselung mit dem Pohlig-Hellman-Verfahren nach Algo. 5.2
	 * @param clear zu verschlüsselnder Klartext
	 * @parem p öffentlicher Schlüssel, Primzahl
	 * @param e öffentlicher Schlüssel, Exponent
	 * @return Verschlüsselter Cipher
	 */
	public static BigInteger encipher(BigInteger clear, BigInteger p, BigInteger e) {
		final BigInteger ONE = new BigInteger("1");
		final BigInteger phiP = p.subtract(ONE);
		
		// (1a) M in Z_p = {0,1,...,p-1}
		BigInteger m = clear.mod(p); // clear mod p
		// (1b) Berechne C = M^e mod p
		BigInteger cipher = m.modPow(e, p);
		// (1c) Rückgabe E_A(M) = C
		return cipher;
	}
	
	/**
	 * Verschlüsselung mit dem Pohlig-Hellman-Verfahren nach Algo. 5.2 (1)
	 * @param clear zu verschlüsselnder Klartext
	 * @parem publicKey öffentlicher Schlüssel der Form (p,e)
	 * @return Verschlüsselter Cipher
	 */
	public static BigInteger encipher(BigInteger clear, BigInteger[] publicKey) {
		return encipher(clear,publicKey[0],publicKey[1]);
	}
	
	/**
	 * Entschlüsselung mit Pohlig-Hellmann-verfahren nach Algo.5.2 (2)
	 * @param cipher
	 * @return
	 */
	public BigInteger decipher(BigInteger cipher) {
		// (2) M = D_A(C) = C^d mod p
		BigInteger m = cipher.modPow(d_, p_);
		return m;
	}
}
