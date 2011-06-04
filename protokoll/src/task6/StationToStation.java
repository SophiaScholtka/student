package task6;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;

import de.tubs.cs.iti.krypto.protokoll.*;
import task3.IDEA;
import task5.Fingerprint;
import task6.StationToStation;

/**
 *
 */

public final class StationToStation implements Protocol
{
	private static final boolean DEBUG = true;

	private static final int RADIX_SEND = 16;


	static private int MinPlayer        = 2; // Minimal number of players
	static private int MaxPlayer        = 2; // Maximal number of players
	static private String NameOfTheGame = "Station-to-Station";
    private Communicator Com;
	
	public void setCommunicator(Communicator com)
	{
	  Com = com;
	}	
	
	public void sendFirst ()
  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen
   * seien dies die Aktionen von Alice.
   */
	{
		if(DEBUG) { System.out.println("DDD| sendFirst() by Alice"); }
		try {
			// Player 0 = Alice; Player 1 = Bob
			// (0)a Alice Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/alice-hash"; // TODO hardcoded hashparam
			
			// (0)a2 Auslesen der Hashparameter
			BigInteger[] keyHash = readIntegers(fileHash,3);
			
			// Speichere eigene Hashkeys
			BigInteger myP = keyHash[0];
			BigInteger myG1 = keyHash[1];
			BigInteger myG2 = keyHash[2];
			
			// (0)b Alice Parameter p, g an Bob senden
			Com.sendTo(1, myP.toString(RADIX_SEND)); // p
			if(DEBUG) { System.out.println("DDD| Alice sendet P an Bob: " + myP); }
			Com.sendTo(1, myG1.toString(RADIX_SEND)); // g1
			if(DEBUG) { System.out.println("DDD| Alice sendet G1 an Bob: " + myG1); }
			
			// (0)c Alice Public RSA (eA, nA) an Bob senden
			// (0)d Alice empfängt Bobs Public RSA (eB, nB)
			
			// (1)a Alice wählt xA zufällig in {1,...,p-2}
			// (1)b Alice berechnet yA = g^xA mod p
			// (1)c Alice sendet yA an Bob
			
			// (2) Bob wählt zufällige xB in {1,...,p-2}
			// (2) Bob berechnet yB = g^xB mod p
			// (2) Bob bestimmt Schlüssel k = yA^ xB mod p
			// (2) Bob bestimmt Signatur SB(yB,yA)=(h(yB,yA))^dB mod nB
			// (3) 
			// (4) 
			// (5) 
			// (6) 
			// (7) 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void receiveFirst ()
  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen
   * seien dies die Aktionen von Bob.
   */
	{
		if(DEBUG) { System.out.println("DDD| receiveFirst() by Bob"); }
		
		// (0) Bob empfängt p und g von Alice
		String sReceive = "";
		sReceive = Com.receive();
		BigInteger foeP = new BigInteger(sReceive,RADIX_SEND);
		if(DEBUG) { System.out.println("DDD| Bob received p of Alice: " + foeP);}
		sReceive = Com.receive();
		BigInteger foeG1 = new BigInteger(sReceive,RADIX_SEND);
		if(DEBUG) { System.out.println("DDD| Bob received G1 of Alice: " + foeG1);}
		
		// (0) Bob empfängt eA und nA von Alice
		
		// (0) Bob sendet Alice seine eB, nB
	}
	
	public String nameOfTheGame ()
	{
		return NameOfTheGame;
	}
	
	public int minPlayer ()
	{
		return MinPlayer;
	}
	
	public int maxPlayer ()
	{
		return MaxPlayer;
	}
	
	/**
	 * Berechnet h(u,v) indem m = u*p+v und h(m)
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
		BigInteger hash = new BigInteger("0"); //TODO hashen irgendwie.
		
		return hash;
	}

	private BigInteger[] readIntegers(String fileHash, int lines) throws IOException {
		
		String[] sKeyHash = readFile(fileHash,lines);
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
		for(int i = 0; i < lines; i++) {
			sLines[i] = br.readLine(); // Zeile i+1
		}
		
		return sLines;
	}
}
