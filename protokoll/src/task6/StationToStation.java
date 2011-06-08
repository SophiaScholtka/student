package task6;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.util.ArrayList;
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
	private final boolean DEBUG = true;
	private final boolean OSCAR_ = false;

	private static final int RADIX_SEND_ = 16;

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

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/hashparameters";
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
			Com.sendTo(1, myP.toString(RADIX_SEND_)); // p
			Com.sendTo(1, myG.toString(RADIX_SEND_)); // g
			if (DEBUG) {
				System.out.println("DDD| A sendet P an B: " + myP);
				System.out.println("DDD| A sendet G an B: " + myG);
			}

			// (0)c A Public RSA (eA, nA) an B senden
			Com.sendTo(1, myRsaE.toString(RADIX_SEND_)); // eA
			Com.sendTo(1, myRsaN.toString(RADIX_SEND_)); // nA
			if (DEBUG) {
				System.out.println("DDD| A sendet RSA eA an B: " + myRsaE);
				System.out.println("DDD| A sendet RSA nA an B: " + myRsaN);
			}

			// (0)d A empfängt B Public RSA (eB, nB)
			System.out.println("Warte auf Public RSA von Bob.");
			String sReceive;
			sReceive = Com.receive();
			BigInteger foeRsaE = new BigInteger(sReceive, RADIX_SEND_); // eB
			sReceive = Com.receive();
			BigInteger foeRsaN = new BigInteger(sReceive, RADIX_SEND_); // nB
			if (DEBUG) {
				System.out.println("DDD| A empfängt RSA eB von B: " + foeRsaE);
				System.out.println("DDD| A empfängt RSA nB von B: " + foeRsaN);
			}

			// (1)a A wählt x zufällig in {1,...,p-2}
			BigInteger help = myP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			// (1)b A berechnet y = g^xA mod p
			BigInteger myY = myG.modPow(myX, myP);
			// (1)c A sendet y an B
			Com.sendTo(1, myY.toString(RADIX_SEND_)); // g1
			if (DEBUG) {
				System.out.println("DDD| A sendet yA an B: " + myY);
			}
			
			
			// (3) Empfange Z(Bob),yB, Ek(SB(yB,yA)))
			sReceive = Com.receive();
			BigInteger foeZ = new BigInteger(sReceive,RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger foeY = new BigInteger(sReceive,RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger foeCiph = new BigInteger(sReceive,RADIX_SEND_);
			if(DEBUG) {
				System.out.println("DDD| Empfangen von Bob:");
				System.out.println("DDD| \t Z(Bob) = " + foeZ);
				System.out.println("DDD| \t yB = " + foeY);
				System.out.println("DDD| \t E_k(S_B(yB,yA)) = " + foeCiph);
			}
			
			
			// (4)a Berechne k = yB ^ xA mod p
			BigInteger k = foeY.modPow(myX, myP);
			
			// Hole IDEA Schlüssel (lowest 128 bit of k)
			BigInteger keyIdea = getIdeaKey(k, 128);

			// (4)b TODO Prüfe Zertifikat von Bob
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

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/hashparameters";
			// (0)a2 Auslesen der Hashparameter
			BufferedReader hashParam = createReader(fileHash);
			Fingerprint hf = new Fingerprint();
			hf.setDebug(true);
			hf.readParam(hashParam); // d.h. Hashparameter sind jetzt im Objekt
										// gespeichert

			// (0) B empfängt p und g von A
			String sReceive = "";
			sReceive = Com.receive();
			BigInteger foeGamalP = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger foeGamalG = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| B received P of A: " + foeGamalP);
				System.out.println("DDD| B received G of A: " + foeGamalG);
			}

			// (0) B empfängt eA und nA von A
			sReceive = Com.receive();
			BigInteger foeRsaE = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger foeRsaN = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| B received RSA e of A: " + foeRsaE);
				System.out.println("DDD| B received RSA n of A: " + foeRsaN);
			}
			// (0) B sendet A seine eB, nB
			Com.sendTo(1, myRsaE.toString(RADIX_SEND_)); // eB
			Com.sendTo(1, myRsaN.toString(RADIX_SEND_)); // nB
			if (DEBUG) {
				System.out.println("DDD| B sendet RSA e an A: " + myRsaE);
				System.out.println("DDD| B sendet RSA n an A: " + myRsaN);
			}

			// B empfängt yA
			sReceive = Com.receive();
			BigInteger foeY = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| B received yA of A: " + foeY);
			}

			// (2)a B wählt x zufällig in {1,...,p-2}
			BigInteger help = foeGamalP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			// (2)b B berechnet y = g^x mod p
			BigInteger myY = foeGamalG.modPow(myX, foeGamalP);
			// (2)c B bestimmt Schlüssel k
			BigInteger k = foeY.modPow(myX, foeGamalP);
			if (DEBUG) {
				System.out.println("DDD| k " + k + "(" + k.bitLength() + ")");
			}

			// (2)d B bestimmt Signatur SB(yB,yA)=(h(yB,yA))^dB mod nB
			BigInteger hashedY = computeHash(hf, foeGamalP, myY, foeY);
			BigInteger sig = hashedY.modPow(myRsaD, myRsaN);

			// (3)a B berechnet A IDEA Key ( 128 lowest bits of k)
			BigInteger keyIdea = getIdeaKey(k, 128);
			if (DEBUG) {
				System.out.println("DDD| IDEA key = " + keyIdea + "("
						+ keyIdea.bitLength() + ")");
			}

			// TODO Berechne Zertifikat Z(Bob)
			BigInteger myZ = new BigInteger("zertifikat",26);
			// TODO Bestimmte Ciffre E_K(S_B(yB,YA))
			BigInteger myCiph = new BigInteger("ciphersignature",26);
			// (3)b B schickt (Z(Bob), yB, Ek(sB(yB,yA))) an A
			// TODO Sende Bobs Zertifikat und Kram.
			Com.sendTo(0, myZ.toString(RADIX_SEND_));
			Com.sendTo(0, myY.toString(RADIX_SEND_));
			Com.sendTo(0, myCiph.toString(RADIX_SEND_));
			if(DEBUG) {
				System.out.println("DDD| (3) Bob sendet an Alice:");
				System.out.println("DDD| \t Z(Bob) = " + myZ);
				System.out.println("DDD| \t yB = " + myY);
				System.out.println("DDD| \t E_k(S_B(yB,yA)) = " + myCiph);
			}
			
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

	private BigInteger getIdeaKey(BigInteger k, int bitCount) {
		String tmp = k.toString(2);
		tmp = tmp.substring(tmp.length() - bitCount);
		BigInteger keyIdea = new BigInteger(tmp, 2);

		return keyIdea;
	}

	/**
	 * Berechnet h(u,v) indem m = u*p+v und h(m) Modifizierte (2) und (5)
	 * 
	 * @param u
	 * @param v
	 * @return
	 */
	private BigInteger computeHash(Fingerprint hf, BigInteger p, BigInteger u,
			BigInteger v) {

		// m = u*p+v
		BigInteger m;
		m = u.multiply(p);
		m = m.add(v);
		byte[] mbyte = m.toByteArray();
		ArrayList<Byte> mlist = new ArrayList<Byte>();
		for(int i=0;i<mbyte.length;i++){
			mlist.add(mbyte[i]);
		}
 		BigInteger hash = hf.hashIt(mlist);
		// FIXME mlist ArrayIndexOutOfBoundsException: -1
		//ArrayList<Byte> mlist = new ArrayList(java.util.Arrays.asList(mbyte));
		//BigInteger hash = hf.hashIt(mlist);

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

	private BufferedReader createReader(String fileHash)
			throws FileNotFoundException {
		FileReader in = new FileReader(fileHash);
		BufferedReader br = new BufferedReader(in);

		return br;
	}
}
