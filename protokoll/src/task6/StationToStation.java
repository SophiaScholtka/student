package task6;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.util.Random;

import chiffre.Grundlagen;
import chiffre.RSA;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;
import task3.IDEA;
import task5.Fingerprint;
import task6.StationToStation;

/**
 *
 */

public final class StationToStation implements Protocol {
	private static final boolean DEBUG = true;

	private static final int RADIX_SEND = 16;

	static private int MinPlayer = 2; // Minimal number of players
	static private int MaxPlayer = 2; // Maximal number of players
	static private String NameOfTheGame = "Station-to-Station";
	private Communicator Com;

	public void setCommunicator(Communicator com) {
		Com = com;
	}

	/**
	 * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien
	 * dies die Aktionen von A.
	 */
	public void sendFirst() {
		if (DEBUG) {
			System.out.println("DDD| sendFirst() by A");
		}
		// Player 0 = A; Player 1 = B
		try {
			// Erhalte RSA-Keys
			BigInteger[] keyRSA = RSA.generateKey(512);
			BigInteger myRsaN = keyRSA[0];
			BigInteger myRsaE = keyRSA[1];
			BigInteger myRsaD = keyRSA[2];

			// TODO Erhalte IDEA-Keys

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/alice-hash";
			BufferedReader hashParam = createReader(fileHash);

			// (0)a2 Auslesen der Hashparameter
			BigInteger[] keyHash = readIntegers(fileHash, 3);
			BigInteger myHashP = keyHash[0];
			BigInteger myHashG1 = keyHash[1];
			BigInteger myHashG2 = keyHash[2];

			// (0)b A Parameter p, g generieren und an B senden
			int bitLength = 512;
			BigInteger[] prime = Grundlagen.generatePrimePQ(bitLength);
			BigInteger myP = prime[0];
			BigInteger myG = Grundlagen.calcPrimeRoot(myP, prime[1]);
			Com.sendTo(1, myP.toString(RADIX_SEND)); // p
			Com.sendTo(1, myG.toString(RADIX_SEND)); // g
			if (DEBUG) {
				System.out.println("DDD| A sendet P an B: " + myP);
				System.out.println("DDD| A sendet G an B: " + myG);
			}

			// (0)c A Public RSA (eA, nA) an B senden
			Com.sendTo(1, myRsaE.toString(RADIX_SEND)); // eA
			Com.sendTo(1, myRsaN.toString(RADIX_SEND)); // nA
			if (DEBUG) {
				System.out.println("DDD| A sendet eA an B: " + myRsaE);
				System.out.println("DDD| A sendet nA an B: " + myRsaN);
			}
			
			// (0)d A empfängt B Public RSA (eB, nB)
			String sReceive;
			sReceive = Com.receive();
			BigInteger foeRsaE = new BigInteger(sReceive, RADIX_SEND); // eB
			if (DEBUG) {
			}
			sReceive = Com.receive();
			BigInteger foeRsaN = new BigInteger(sReceive, RADIX_SEND); // eB
			if (DEBUG) {
				System.out.println("DDD| A empfängt nB von B: " + foeRsaN);
				System.out.println("DDD| A empfängt eB von B: " + foeRsaE);
			}
			
			
			
			// (1)a A wählt x zufällig in {1,...,p-2}
			BigInteger help = myHashP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE,
					help);
			// (1)b A berechnet y = g^xA mod p
			BigInteger myY = myHashG1.modPow(myX, myHashP);
			// (1)c A sendet y an B
			Com.sendTo(1, myY.toString(RADIX_SEND)); // g1
			if (DEBUG) {
				System.out.println("DDD| A sendet yA an B: " + myY);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies
	 * die Aktionen von B.
	 */
	public void receiveFirst() {
		if (DEBUG) {
			System.out.println("DDD| receiveFirst() by B");
		}
		try {
			// Erhalte RSA-Keys
			BigInteger[] keyRSA = RSA.generateKey(512);
			BigInteger myRsaN = keyRSA[0];
			BigInteger myRsaE = keyRSA[1];
			BigInteger myRsaD = keyRSA[2];

			// TODO Erhalte IDEA-Keys

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/bob-hash";
			
			// (0)a2 Auslesen der Hashparameter
			BigInteger[] keyHash = readIntegers(fileHash, 3);
			BigInteger myHashP = keyHash[0];
			BigInteger myHashG1 = keyHash[1];
			BigInteger myHashG2 = keyHash[2];

			// (0) B empfängt p und g von A
			String sReceive = "";
			sReceive = Com.receive();
			BigInteger foeP = new BigInteger(sReceive, RADIX_SEND);
			sReceive = Com.receive();
			BigInteger foeG = new BigInteger(sReceive, RADIX_SEND);
			if (DEBUG) {
				System.out.println("DDD| B received p of A: " + foeP);
				System.out.println("DDD| B received G1 of A: " + foeG);
			}

			// (0) B empfängt eA und nA von A
			sReceive = Com.receive();
			BigInteger foeRsaE = new BigInteger(sReceive, RADIX_SEND);
			sReceive = Com.receive();
			BigInteger foeRsaN = new BigInteger(sReceive, RADIX_SEND);
			if (DEBUG) {
				System.out.println("DDD| B received e of A: " + foeRsaE);
				System.out.println("DDD| B received n of A: " + foeRsaN);
			}
			// (0) B sendet A seine eB, nB
			Com.sendTo(1, myRsaE.toString(RADIX_SEND)); // eA
			Com.sendTo(1, myRsaN.toString(RADIX_SEND)); // nA
			if (DEBUG) {
				System.out.println("DDD| B sendet e an A: " + myRsaE);
				System.out.println("DDD| B sendet n an A: " + myRsaN);
			}

			
			
			// B empfängt yA
			sReceive = Com.receive();
			BigInteger foeY = new BigInteger(sReceive, RADIX_SEND);
			if (DEBUG) {
				System.out.println("DDD| B received yA of A: " + foeY);
			}
			

			// (2)a B wählt x zufällig in {1,...,p-2}
			BigInteger help = myHashP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE,
					help);
			// (2)b B berechnet y = g^x mod p
			BigInteger myY = myHashG1.modPow(myX, myHashP);
			// (2)c B bestimmt Schlüssel k
			BigInteger k = foeY.modPow(myX, foeP);
			
			// (2)d B bestimmt Signatur SB(yB,yA)=(h(yB,yA))^dB mod nB
			BigInteger hashedY = computeHash(foeP, myY, foeY);
			BigInteger sig = hashedY.modPow(myRsaD, myRsaN);
			
			// (3) B schickt (Z(Bob), yB, Ek(sB(yB,yA))) an A
			//TODO Sende Bobs Zertifikat und Kram.
			
			FileInputStream fis = new FileInputStream("bla");
			
			
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public String nameOfTheGame() {
		return NameOfTheGame;
	}

	public int minPlayer() {
		return MinPlayer;
	}

	public int maxPlayer() {
		return MaxPlayer;
	}

	/**
	 * Berechnet h(u,v) indem m = u*p+v und h(m)
	 * Modifizierte (2) und (5)
	 * 
	 * @param u
	 * @param v
	 * @return
	 */
	private BigInteger computeHash(BigInteger p, BigInteger u, BigInteger v) {
		
		// m = u*p+v
		BigInteger m;
		m = u.multiply(p);
		m = m.add(v);

		Fingerprint h = new Fingerprint();
//		h.readParam(param);
//		h.hash(cleartext, ciphertext);
		BigInteger hash = new BigInteger("0"); // TODO Hashen mit Fingerprint

		return hash;
	}

	private BigInteger[] readIntegers(String fileHash, int lines)
			throws IOException {

		String[] sKeyHash = readFile(fileHash, lines);
		BigInteger[] keyHash = new BigInteger[lines];
		for (int i = 0; i < sKeyHash.length; i++) {
			keyHash[i] = new BigInteger(sKeyHash[i]);

		}

		return keyHash;
	}

	private String[] readFile(String fileHash, int lines) throws IOException {
		FileReader in = new FileReader(fileHash);
		BufferedReader br = new BufferedReader(in);
		String[] sLines = new String[lines]; // Return
		for (int i = 0; i < lines; i++) {
			sLines[i] = br.readLine(); // Zeile i+1
		}

		return sLines;
	}
	
	private BufferedReader createReader(String fileHash) throws FileNotFoundException {
		FileReader in = new FileReader(fileHash);
		BufferedReader br = new BufferedReader(in);
		
		return br;
	}
}
