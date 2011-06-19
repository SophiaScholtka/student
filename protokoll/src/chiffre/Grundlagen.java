package chiffre;

import java.math.BigInteger;
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
			  q = BigInteger.probablePrime(bitLength-1, random);
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
			  q = BigInteger.probablePrime(bitLength-1, random);
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
}
