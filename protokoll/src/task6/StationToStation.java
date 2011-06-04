package task6;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
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
			String fileHash = "../Station-to-Station/hashparam"; // TODO hardcoded hashparam
			Fingerprint fp = new Fingerprint();
			FileReader in = new FileReader(fileHash);
			BufferedReader br = new BufferedReader(in);
			fp.readParam(br);
			BigInteger[] keyHash = new BigInteger[3];
			keyHash[0] = new BigInteger("1234");
			keyHash[1] = new BigInteger("5678");
			keyHash[2] = new BigInteger("9000");
			
			// (0)b Alice Parameter p, g an Bob senden
			Com.sendTo(1, keyHash[0].toString()); // p
//			Com.sendTo(1, keyHash[1].toString()); // g1
			// (0)c Alice Public RSA (eA, nA) an Bob senden
			// (0)d Bob sendet seinen Public RSA (eB, nB) an Alice
			
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
		} catch (FileNotFoundException e) {
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
		
		// (0) Bob empfängt p und g
		String sReceive = "";
		BigInteger[] keyFoe = new BigInteger[3];
		sReceive = Com.receive();
		System.out.println("Received: " + sReceive);
		keyFoe[0] = new BigInteger(sReceive);
//		sReceive = Com.receive();
//		System.out.println(sReceive);
//		keyFoe[1] = new BigInteger(sReceive);
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
}
