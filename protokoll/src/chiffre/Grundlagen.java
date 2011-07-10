package chiffre;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public class Grundlagen {

	public static BigInteger[] generatePrimePQ(int bitLength) {

		// erzeuge sichere Primzahl p, min 512 bits
		Random random = new Random();
		boolean isPrime = false;
		BigInteger p = BigIntegerUtil.TWO;
		BigInteger q = BigIntegerUtil.TWO;
		do {
			q = BigInteger.probablePrime(bitLength - 1, random);
			p = q.multiply(BigIntegerUtil.TWO);
			p = p.add(BigInteger.ONE);

			isPrime = p.isProbablePrime(50);
		} while (!isPrime);

		BigInteger[] back = new BigInteger[2];
		back[0] = p;
		back[1] = q;
		return back;
	}

	public static BigInteger generatePrime(int bitLength) {

		// erzeuge sichere Primzahl p, min 512 bits
		Random random = new Random();
		boolean isPrime = false;
		BigInteger p = BigIntegerUtil.TWO;
		BigInteger q = BigIntegerUtil.TWO;
		do {
			q = BigInteger.probablePrime(bitLength - 1, random);
			p = q.multiply(BigIntegerUtil.TWO);
			p = p.add(BigInteger.ONE);

			isPrime = p.isProbablePrime(50);
		} while (!isPrime);

		return p;
	}

	/**
	 * Algo 7.3
	 * 
	 * @param bitLength
	 * @return
	 */
	public static BigInteger calcPrimeRoot(BigInteger p, BigInteger q) {

		// Generiere primitive Wurzel g in Z_p^*
		boolean checkRoot = false;
		BigInteger g = BigIntegerUtil.TWO;
		BigInteger biNeg1 = new BigInteger("-1");
		biNeg1 = biNeg1.mod(p);
		do {
			g = generateReducedRest(p);
			boolean isNotOne = !g.equals(BigInteger.ONE);
			boolean isNotP1 = !g.equals(p.subtract(BigInteger.ONE));
			if (isNotOne || isNotP1) {
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
	 * 
	 * @param modulus
	 * @return
	 */
	private static BigInteger generateReducedRest(BigInteger modulus) {

		BigInteger reducedRest = BigInteger.ZERO; // Rückgabe
		Random randomGenerator = new Random();
		boolean check = false;
		while (!check) {
			reducedRest = BigIntegerUtil.randomSmallerThan(modulus,
					randomGenerator);

			check = reducedRest.gcd(modulus).equals(BigInteger.ONE);
		}

		return reducedRest;

	}

	public static BigInteger elGamalDecipher(BigInteger code, BigInteger priX,
			BigInteger pubP) {
		BigInteger a = code.mod(pubP);
		BigInteger b = code.divide(pubP);
		BigInteger z = (a.modPow(priX, pubP)).modInverse(pubP);
		BigInteger back = (z.multiply(b)).mod(pubP);
		return back;
	}

	public static BigInteger elGamalEncipher(BigInteger mess, BigInteger pubP,
			BigInteger pubG, BigInteger pubY) {
		BigInteger a = pubG.modPow(mess, pubP);
		BigInteger b = mess.multiply(pubY.modPow(mess, pubP));
		BigInteger back = a.add(b.multiply(pubP));
		return back;

	}

	/**
	 * @deprecated
	 * @param mess
	 * @param pubP
	 * @param pubG
	 * @param pubY
	 * @param priX
	 * @return
	 */
	public static BigInteger elGamalSignOld(BigInteger mess, BigInteger pubP,
			BigInteger pubG, BigInteger pubY, BigInteger priX) {
		// Algo 7.8 (1) Signiere Nachricht M
		final BigInteger BIGINTP1 = pubP.subtract(BigInteger.ONE); // P-1

		// (1a) Zufälliges k in {1,...,p-2} mit ggt(k,p-1)=1 wählen
		BigInteger lower = BigInteger.ONE;
		BigInteger upper = pubP.subtract(BigIntegerUtil.TWO);
		BigInteger myK;
		boolean check = true;
		do {
			myK = BigIntegerUtil.randomBetween(lower, upper);
			check = !(myK.gcd(BIGINTP1).equals(BigInteger.ONE));
		} while (check);

		// (1b) Berechne r = g^k mod p
		BigInteger myR;
		myR = pubG.modPow(myK, pubP); // r = g^k mod p

		// (1c) Berechne k^(-1) mod (p-1)
		BigInteger myKN = myK.modInverse(BIGINTP1); // k^(-1) mod (p-1)

		// (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		BigInteger myM = mess.mod(pubP);

		// (1e) Berechne s = (M-xr)k^(-1) mod (p-1)
		BigInteger myS = priX.multiply(myR); // x * r
		myS = myM.subtract(myS); // M-xr
		myS = myS.multiply(myKN); // (M-xr)*k^(-1)
		myS = myS.mod(BIGINTP1); // (M-xr)*k^(-1) mod p-1

		// Modifikation: C = (r,s) zu C' = r + s*p geändert
		BigInteger myC = myS.multiply(pubP);
		myC = myC.add(myR);
		return myC;
	}

	/**
	 * @deprecated
	 * @param mess
	 * @param sig
	 * @param pubP
	 * @param pubG
	 * @param pubY
	 * @return
	 */
	public static boolean elGamalVerifyOld(BigInteger mess, BigInteger sig,
			BigInteger pubP, BigInteger pubG, BigInteger pubY) {
		// Algo 7.8 - (2) Prüfe Signatur (r,s) auf M
		boolean isBad = false;
		// (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		mess = mess.mod(pubP); // M mod P
		// Ermittle s = c mod p
		// BigInteger s = sig.divideAndRemainder(pubP)[0];
		BigInteger s = sig.mod(pubP);
		// Ermittle r = c % p
		BigInteger r = sig.divide(pubP);
		// BigInteger r = sig.divideAndRemainder(pubP)[1];

		// (2b) Prüfe ob 1 <= r <= p-1; false: abbruch
		boolean ifLess = (r.compareTo(BigInteger.ONE) == -1);
		boolean ifMore = (r.compareTo(pubP.subtract(BigInteger.ONE)) == 1);
		if (ifLess || ifMore) {
			isBad = true;
		}

		// (2c) Berechne v1 = y^r r^s mod p
		BigInteger v1 = pubY.modPow(r, pubP);
		BigInteger h = r.modPow(s, pubP);
		v1 = v1.multiply(h);
		v1 = v1.mod(pubP);

		// (2c) Berechne v2 = g^M mod p
		BigInteger v2 = pubG.modPow(mess, pubP);

		if (!v2.equals(v1)) {
			isBad = true;
		}

		// (2d) Akzeptiere, wenn v1==v2
		// return !isBad;
		return v2.equals(v1);
	}

	/**
	 * Algo 7.8 Signierung von Nachricht M
	 * 
	 * @param mess
	 *            zu signierende Nachricht
	 * @param pubP
	 *            öffentlicher Schlüssel p (ElGamal)
	 * @param pubG
	 *            öffentlicher Schlüssel g (ElGamal)
	 * @param pubY
	 *            öffentlicher Schlüssel y (ElGamal)
	 * @param priX
	 *            privater Schlüssel x (ElGamal)
	 * @return Signatur (r,s) in Form von (r + s * p) zurück
	 */
	public static BigInteger elGamalSign(BigInteger mess, BigInteger pubP,
			BigInteger pubG, BigInteger pubY, BigInteger priX) {

		// Konstanten
		final BigInteger BIGINTP1 = pubP.subtract(BigInteger.ONE); // P-1

		// Schlüssel
		BigInteger myP = pubP;
		BigInteger myG = pubG;
		// BigInteger myY = pubY;
		BigInteger myX = priX;

		// (1a) Zufälliges k in {1,...,p-2} mit ggt(k,p-1)=1 wählen
		BigInteger lower = BigInteger.ONE;
		BigInteger upper = myP.subtract(BigIntegerUtil.TWO);
		BigInteger myK;
		boolean check = true;
		do {
			myK = BigIntegerUtil.randomBetween(lower, upper);
			check = !(myK.gcd(BIGINTP1).equals(BigInteger.ONE));
		} while (check);

		// (1b) Berechne r = g^k mod p
		BigInteger myR = myG.modPow(myK, myP); // r = g^k mod p

		// (1c) Berechne k^(-1) mod (p-1)
		BigInteger myKN = myK.modInverse(BIGINTP1); // k^(-1) mod (p-1)

		// (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		BigInteger myM = mess.mod(myP);

		// (1e) Berechne s = (M-xr)k^(-1) mod (p-1)
		BigInteger myS = myX.multiply(myR); // x * r
		myS = myM.subtract(myS); // M-xr
		myS = myS.multiply(myKN); // (M-xr)*k^(-1)
		myS = myS.mod(BIGINTP1); // (M-xr)*k^(-1) mod p-1

		// Modifikation: C = (r,s) zu C' = r + s*p geändert
		BigInteger myC = myS.multiply(myP);
		myC = myC.add(myR);
		
		//System.out.println("S = " + myS);
		//System.out.println("r = " + myR);
		
		// (1f) Signatur (r,s) zurück
		return myC;
	}

	/**
	 * Algo 7.8 Prüfung der Signatur (r,s) mit Nachricht M
	 * @param mess die zu prüfenden Nachricht M
	 * @param sig die zu prüfende Signatur von M
	 * @param pubP öffentlicher Schlüssel p (ElGamal)
	 * @param pubG öffentlicher Schlüssel g (ElGamal)
	 * @param pubY öffentlicher Schlüssel y (ElGamal)
	 * @return true wenn die Signatur gilt, false wenn sie ungültig ist
	 */
	public static boolean elGamalVerify(BigInteger mess, BigInteger sig,
			BigInteger pubP, BigInteger pubG, BigInteger pubY) {

		// Lese Cipher (modifizierte Signatur), C'=r+s*p
		BigInteger foeC = sig; // C' = r + s*p
		// Lese Klartext
		BigInteger foeM = mess;
		// (1d) Nachricht Element M in Z_p^*: M mod p, ggt(M,p)=1
		foeM = foeM.mod(pubP); // M mod P

		// Ermittle s = c div p
		BigInteger foeS = foeC.divideAndRemainder(pubP)[0]; // Signatur
		// Ermittle r = c % p
		BigInteger foeR = foeC.divideAndRemainder(pubP)[1]; // r
		//System.out.println("S = " + foeS);
		//System.out.println("r = " + foeR);

		// (2b) Prüfe ob 1 <= r <= p-1; false: abbruch
		boolean ifLess = (foeR.compareTo(BigInteger.ONE) == -1);
		boolean ifMore = (foeR.compareTo(pubP.subtract(BigInteger.ONE)) == 1);
		if (ifLess || ifMore) {
			return false;
		}

		// (2c) Berechne v1 = y^r r^s mod p
		BigInteger foeV1 = pubY.modPow(foeR, pubP);
		BigInteger h = foeR.modPow(foeS, pubP);
		foeV1 = foeV1.multiply(h);
		foeV1 = foeV1.mod(pubP);

		// (2c) Berechne v2 = g^M mod p
		BigInteger foeV2 = pubG.modPow(foeM, pubP);

		// (2d) Akzeptiere, wenn v1==v2
		return foeV2.equals(foeV1);
	}
	
	/**
	 * Liest gegebene Datei ein
	 * @param path Pfad zur Datei
	 * @param amount Anzahl der Zeichen pro BigInteger
	 * @return Inhalt des Vertrages, pro BigInteger zwei Zeichen des Vertrages
	 */
	public static BigInteger[] readFile(String path, int amount) {
		if(amount < 1) { 
			amount = 1;
		}
		try {
			ArrayList<BigInteger> readChars = new ArrayList<BigInteger>();
			
			BufferedReader file = new BufferedReader(new FileReader(path));
			int read;
			while (file.ready()) {
				read = file.read();
				
				BigInteger big;
				big = new BigInteger("" + read);
				for(int i = 1 ; i < amount; i++ ) {
					big = big.shiftLeft(8);
					
					if (file.ready()) {
						read = file.read();
					} else { 
						// Fülle mit Leerzeichen auf
						read = 32;
					}
					
					BigInteger big2;
					big2 = new BigInteger("" + read);
					big = big.add(big2);
				}
				
				readChars.add(big);
			}
			
			BigInteger[] back = new BigInteger[readChars.size()];
			int index = 0;
			for (Iterator<BigInteger> it = readChars.iterator(); it.hasNext();) {
				BigInteger bigInteger = (BigInteger) it.next();
				back[index] = bigInteger;
				index = index + 1;
			}
			
			return back;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
