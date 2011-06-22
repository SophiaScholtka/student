package task6;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Random;

import chiffre.Grundlagen;
import chiffre.RSA;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;
import sun.security.x509.KeyIdentifier;
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
	private BigInteger zwei = new BigInteger("2",10);

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
		//TEst
		String something = "hay You!";
		BigInteger some = StringToBigInt(something);
		BigIntToString(some);
		
		//kleine Testrunde für den Idea-Kram
		//BigInteger [][] in doEncipher und Ergebnis in doDecipher ergibt das gleiche BigInteger[][],
		//der Fehler muss also in useIDEA und/oder useReverseIDEA stecken
		/*if (DEBUG){
			BigInteger test = new BigInteger("127",10);
			BigInteger testa[][] = convertForIDEA(test);
			BigInteger test2 = convertFromIDEA(testa);
			//System.out.println(">>>test "+test);
			//System.out.println(">>>testarr "+testa[0][0]+"\t"+testa[0][1]+"\t"+testa[0][2]+"\t"+testa[0][3]);
			//System.out.println(">>>test2 "+test2);
			test = (zwei.pow(1024));
			BigInteger testar[][] = convertForIDEA(test);
			test2 = convertFromIDEA(testar);
			//System.out.println(">>>test "+test);
			//System.out.println(">>>testarr "+testar[0][0]+"\t"+testar[0][1]+"\t"+testar[0][2]+"\t"+testar[0][3]+"\t"+testar[1][0]+"\t"+testar[1][1]+"\t"+testar[1][2]+"\t"+testar[1][3]);
			//System.out.println(">>>test2 "+test2);
			testar = convertForIDEA(test2);
			//System.out.println(">>>testarr "+testar[0][0]+"\t"+testar[0][1]+"\t"+testar[0][2]+"\t"+testar[0][3]+"\t"+testar[1][0]+"\t"+testar[1][1]+"\t"+testar[1][2]+"\t"+testar[1][3]);
			//System.out.println(">>>test2 "+test2);
			test = new BigInteger(123, new Random());
			BigInteger testarr[][] = convertForIDEA(test);
			test2 = convertFromIDEA(testarr);
			//System.out.println(">>>test "+test);
			//System.out.println(">>>testarr "+testarr[0][0]+"\t"+testarr[0][1]+"\t"+testarr[0][2]+"\t"+testarr[0][3]+"\t"+testarr[1][0]+"\t"+testarr[1][1]+"\t"+testarr[1][2]+"\t"+testarr[1][3]);
			//System.out.println(">>>test2 "+test2);
			BigInteger dummykey = new BigInteger(222, new Random());
			BigInteger realkey[] = getIdeaKey(dummykey,128);
			BigInteger rest = useIDEA(test,realkey);
			rest = useReverseIDEA(rest,realkey);
			//System.out.println(">>>rest"+rest);
		}*/
		
		if (DEBUG) {
			System.out.println("DDD| sendFirst() by A");
		}
		// Player 0 = A; Player 1 = B
		try {
			// Erhalte RSA-Keys
			System.out.print("Generiere RSA Key für mich... Augenblick...");
			BigInteger[] keyRSA = RSA.generateKey(1024);
			BigInteger myRsaN = keyRSA[0];
			BigInteger myRsaE = keyRSA[1];
			BigInteger myRsaD = keyRSA[2];
			System.out.println("\t [OK]");

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/hashparameters";
			BufferedReader hashParam = createReader(fileHash);

			Fingerprint hf = new Fingerprint();
			hf.setDebug(DEBUG);
			hf.readParam(hashParam); // d.h. Hashparameter sind jetzt im Objekt
										// gespeichert
			
			// (0)b1 A Parameter p, g generieren
			System.out.print("Generiere El-Gamal Key für mich... "
					+ "Augenblick...");
			int bitLength = 512;
			BigInteger[] prime = Grundlagen.generatePrimePQ(bitLength);
			BigInteger myGamalP = prime[0];
			BigInteger myGamalG = Grundlagen.calcPrimeRoot(myGamalP, prime[1]);
			System.out.println("\t [OK]");

			// (0)b2 Parameter p, g an B senden
			Com.sendTo(1, myGamalP.toString(RADIX_SEND_)); // p
			Com.sendTo(1, myGamalG.toString(RADIX_SEND_)); // g
			if (DEBUG) {
				System.out.println("DDD| (0) A sendet an B:");
				System.out.println("DDD| \t p = " + myGamalP);
				System.out.println("DDD| \t g = " + myGamalG);
				
			}

			// (0)c A Public RSA (eA, nA) an B senden
			Com.sendTo(1, myRsaE.toString(RADIX_SEND_)); // eA
			Com.sendTo(1, myRsaN.toString(RADIX_SEND_)); // nA
			if (DEBUG) {
				System.out.println("DDD| (0) A sendet RSA an B:");
				System.out.println("DDD| \t eA = " + myRsaE);
				System.out.println("DDD| \t nA = " + myRsaN);
			}

			// (0)d A empfängt B Public RSA (eB, nB)
			String sReceive;
			sReceive = Com.receive();
			BigInteger partnerRsaE = new BigInteger(sReceive, RADIX_SEND_); // eB
			sReceive = Com.receive();
			BigInteger partnerRsaN = new BigInteger(sReceive, RADIX_SEND_); // nB
			if (DEBUG) {
				System.out.println("DDD| (0) A empfängt RSA von B:");
				System.out.println("DDD| \t eB = " + partnerRsaE);
				System.out.println("DDD| \t nB = " + partnerRsaN);
			}

			// (1)a A wählt x zufällig in {1,...,p-2}
			BigInteger help = myGamalP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			// (1)b A berechnet y = g^xA mod p
			BigInteger myY = myGamalG.modPow(myX, myGamalP);
			// (1)c A sendet y an B
			Com.sendTo(1, myY.toString(RADIX_SEND_)); // yA
			if (DEBUG) {
				System.out.println("DDD| (1) A sendet yA an B: " + myY);
			}

			// (3) Empfange Z(Bob),yB, Ek(SB(yB,yA)))
			sReceive = Com.receive();
			String partnerID = sReceive;
			sReceive = Com.receive();
			BigInteger partnerEN = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerSig = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerY = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerCiph = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| (3) Empfangen von Bob:");
				System.out.println("DDD| \t ID(Bob)         = " + partnerID);
				System.out.println("DDD| \t eBnB            = " + partnerEN);
				System.out.println("DDD| \t D_T(ID,eBnB)    = " + partnerSig);
				System.out.println("DDD| \t yB              = " + partnerY);
				System.out.println("DDD| \t E_k(S_B(yB,yA)) = " + partnerCiph);
			}

			// (4)a Berechne k = yB ^ xA mod p
			BigInteger k = partnerY.modPow(myX, myGamalP);
			if (DEBUG) {
				System.out.println("DDD| (4) k = " + k);
			}

			// Hole IDEA Schlüssel (lowest 128 bit of k)
			BigInteger keyIdea[] = getIdeaKey(k, 128);
			if (DEBUG) {
				System.out.println("DDD| Idea Schlüssel: " + keyIdea + " ("
						+ keyIdea.length + ")");
			}

			// (4)b Prüfe Zertifikat von Bob
			boolean check = checkCertificate(partnerID,partnerEN,partnerSig);
			// (4)c Prüfe S_B(yB,yA)^eB mod nB = h(yB,yA)
			BigInteger hashed = computeHash(hf, myGamalP, partnerY, myY);
			BigInteger sig = useReverseIDEA(partnerCiph,keyIdea);
			BigInteger unsig = sig.modPow(partnerRsaE, partnerRsaN);
			if (!unsig.equals(hashed.mod(partnerRsaN))) {
				//check=false;
				System.out.println("Prüfung S_B(yB,yA)^eB mod nB = h(yB,yA) fehlgeschlagen.");
				//System.out.println(">>>h = "+hashed);
				//System.out.println(">>>sig = "+sig);
				//System.out.println(">>>unsig ="+unsig);
			}  else {
				if (DEBUG) System.out.println("DDD| S_B(yB,yA)^eB mod nB = h(yB,yA) erfolgreich geprüft.");
			}
			//nur weiter machen, falls es tatsächlich Bob ist
			if(check) {
				// (5) Berechne S_A(yA,yB)=h(yA,YB)^dA mod nA
				BigInteger hashedY = computeHash(hf, myGamalP, myY, partnerY);
				sig = hashedY.modPow(myRsaD, myRsaN);
				// (6)a Berechne Zertifikat Z(Alice)
				byte[] dataE = myRsaE.toByteArray();
				byte[] dataN = myRsaN.toByteArray();
				byte[] data = new byte[dataE.length+dataN.length];
				for(int i=0;i<dataE.length;i++){
					data[i]=dataE[i];
				}
				for(int i=0;i<dataN.length;i++){
					data[dataE.length+i]=dataN[i];
				}
				Certificate myCert = TrustedAuthority.newCertificate(data);
				// (6)b Bestimmte Ciffre E_K(S_A(yA,yB))
				// d.h. einfach Idea mit Schlüssel k auf BigInteger sig anwenden
				
				BigInteger myEk = useIDEA(sig, keyIdea);
				//BigInteger myEk = sig;
				
				// (6)c A schickt (Z(Alice), yA, Ek(S_A(yA,yB))) an B
				System.out.println(myCert.getID());
				Com.sendTo(1, myCert.getID());
				BigInteger myData = new BigInteger(myCert.getData());
				Com.sendTo(1, myData.toString(RADIX_SEND_));
				Com.sendTo(1, myCert.getSignature().toString(RADIX_SEND_));
				Com.sendTo(1, myY.toString(RADIX_SEND_));
				Com.sendTo(1, myEk.toString(RADIX_SEND_));
				if (DEBUG) {
					System.out.println("DDD| (6) Alice sendet an Bob:");
					System.out.println("DDD| \t ID(Alice)         = " + myCert.getID());
					System.out.println("DDD| \t eA,nA           = " + myData.toString());
					System.out.println("DDD| \t D_T(ID,eA,nA)   = " + myCert.getSignature());
					System.out.println("DDD| \t yA              = " + myY);
					System.out.println("DDD| \t E_k(S_A(yA,yB)) = " + myEk);
				}
				// (7) nichts tun
				// (8) beginne Kommunikation
				boolean communicate = true;
				while(communicate){
					System.out.println("Möchten Sie eine Nachricht senden?");
					communicate = askYN();
					if (communicate==false) break;
					System.out.println("Geben Sie eine Nachricht ein.");
					String message = askString();
					BigInteger code = StringToBigInt(message);
					//System.out.println(">>>code "+code.toString(RADIX_SEND_));
					code = useIDEA(code,keyIdea);
					Com.sendTo(1, code.toString(RADIX_SEND_));
					message = Com.receive();
					code = new BigInteger(message, RADIX_SEND_);
					code = useReverseIDEA(code,keyIdea);
					
					message=BigIntToString(code);
					System.out.print("Nachricht empfangen: "+message);
					
				}
			} else {
				System.err.println("Cheater!");
				System.err.println("abort game");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private BigInteger StringToBigInt(String message) {
		char temp;
		if (message.length()<1) return BigInteger.ZERO;
		temp = message.charAt(message.length()-1);
		BigInteger result = BigInteger.valueOf(temp);
		for(int i=message.length()-2;i>=0;i--){
			temp = message.charAt(i);
			//System.out.println(">>>temp is "+temp);
			result = result.add(BigInteger.valueOf(temp));
			result = result.multiply(zwei.pow(16));
			//System.out.println(">>>result is "+result.toString(RADIX_SEND_));
		}
		return result;
	}

	private String BigIntToString(BigInteger code) {
		String back = "";
		BigInteger temp0;
		char temp1;
		while (!code.equals(BigInteger.ZERO)){
			temp0 = code.mod(zwei.pow(16));
			//System.out.println(">>>temp0 is "+temp0.toString(RADIX_SEND_));
			temp1 = (char) temp0.intValue();
			System.out.println(">>>temp1 is"+temp1);
			code = code.divide(zwei.pow(16));
			back = back+""+temp1;
			//System.out.println(">>>code is "+code.toString(RADIX_SEND_));
		}
		System.out.println();
		return back;
	}

	private boolean checkCertificate(String partnerID, BigInteger partnerEN,
			BigInteger partnerSig) {
		BigInteger modTA = TrustedAuthority.getModulus();
		BigInteger expTA = TrustedAuthority.getPublicExponent();
		BigInteger partnerData = partnerSig.modPow(expTA, modTA);
		
		BigInteger M;
		MessageDigest sha = null;
		byte[] digest;

		// ID und EN zusammenhashen

		// make SHA Hashfunction
		try {
			sha = MessageDigest.getInstance("SHA");
		} catch (Exception e) {
			System.out.println("Could not create message digest! Exception "
					+ e.toString());
		}

		// Hashwert bestimmen
		sha.update(partnerID.getBytes());
		sha.update(partnerEN.toByteArray());
		digest = sha.digest();
		//digest in BigInteger umwandeln
		M = new BigInteger(digest);
		//Vergleichen
		if (M.mod(modTA).equals(partnerData.mod(modTA))){
			System.out.println("Zertifikat erfolgreich überprüft.");
			return true;
		}
		System.err.println("Falsches Zertifikat!");
		return false;
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
			System.out.print("Generiere RSA Key für mich... Augenblick...");
			BigInteger[] keyRSA = RSA.generateKey(1024);
			BigInteger myRsaN = keyRSA[0];
			BigInteger myRsaE = keyRSA[1];
			BigInteger myRsaD = keyRSA[2];
			System.out.println("\t [OK]");

			// (0)a A Nutzerangabe, wo Hashparameter
			String fileHash = "../Station-to-Station/hashparameters";
			// (0)a2 Auslesen der Hashparameter
			BufferedReader hashParam = createReader(fileHash);
			Fingerprint hf = new Fingerprint();
			hf.setDebug(DEBUG);
			hf.readParam(hashParam); // d.h. Hashparameter sind jetzt im Objekt
										// gespeichert

			// (0) B empfängt p und g von A
			String sReceive = "";
			sReceive = Com.receive();
			BigInteger partnerGamalP = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerGamalG = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| (0) B empfängt von A:");
				System.out.println("DDD| \t p = " + partnerGamalP);
				System.out.println("DDD| \t g = " + partnerGamalG);
			}

			// (0) B empfängt eA und nA von A
			sReceive = Com.receive();
			BigInteger partnerRsaE = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerRsaN = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| (0) B empfängt RSA von A:");
				System.out.println("DDD| \t e = " + partnerRsaE);
				System.out.println("DDD| \t n = " + partnerRsaN);
			}

			// (0) B sendet A seine eB, nB
			Com.sendTo(0, myRsaE.toString(RADIX_SEND_)); // eB
			Com.sendTo(0, myRsaN.toString(RADIX_SEND_)); // nB
			if (DEBUG) {
				System.out.println("DDD| (0) B sendet RSA an A:");
				System.out.println("DDD| \t e = " + myRsaE);
				System.out.println("DDD| \t n = " + myRsaN);
			}

			// (1) B empfängt yA
			sReceive = Com.receive();
			BigInteger partnerY = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| (1) B received yA of A: " + partnerY);
			}

			// (2)a B wählt x zufällig in {1,...,p-2}
			BigInteger help = partnerGamalP.subtract(BigIntegerUtil.TWO);
			BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			// (2)b B berechnet y = g^x mod p
			BigInteger myY = partnerGamalG.modPow(myX, partnerGamalP);
			// (2)c B bestimmt Schlüssel k
			BigInteger k = partnerY.modPow(myX, partnerGamalP);
			if (DEBUG) {
				System.out.println("DDD| (2) Bob berechnet:");
				System.out.println("DDD| \t x = " + myX);
				System.out.println("DDD| \t y = " + myY);
				System.out.println("DDD| \t k = " + k + "(" + k.bitLength()
						+ ")");
			}

			// (2)d B bestimmt Signatur S_B(yB,yA)=(h(yB,yA))^dB mod nB
			BigInteger hashed = computeHash(hf, partnerGamalP, myY, partnerY);
			BigInteger sig = hashed.modPow(myRsaD, myRsaN);
			if (DEBUG){
				//System.out.println(">>>hashed is "+hashed);
				//System.out.println(">>>sig is "+sig);
			}

			// (2)e B berechnet IDEA Key ( 128 lowest bits of k)
			BigInteger keyIdea[] = getIdeaKey(k, 128);
			if (DEBUG) {
				System.out.println("DDD| IDEA key = " + keyIdea + " ("
						+ keyIdea.length + ")");
			}

			// (3)a Berechne Zertifikat Z(Bob)
			byte[] dataE = myRsaE.toByteArray();
			byte[] dataN = myRsaN.toByteArray();
			byte[] data = new byte[dataE.length+dataN.length];
			for(int i=0;i<dataE.length;i++){
				data[i]=dataE[i];
			}
			for(int i=0;i<dataN.length;i++){
				data[dataE.length+i]=dataN[i];
			}
			Certificate myCert = TrustedAuthority.newCertificate(data);
			// (3)b Bestimmte Ciffre E_K(S_B(yB,yA))
			// d.h. einfach Idea mit Schlüssel k auf BigInteger sig anwenden
			BigInteger myEk = useIDEA(sig, keyIdea);
			//BigInteger myEk = sig;
			
			// (3)c B schickt (Z(Bob), yB, Ek(sB(yB,yA))) an A
			System.out.println(myCert.getID());
			Com.sendTo(0, myCert.getID());
			BigInteger myData = new BigInteger(myCert.getData());
			Com.sendTo(0, myData.toString(RADIX_SEND_));
			Com.sendTo(0, myCert.getSignature().toString(RADIX_SEND_));
			Com.sendTo(0, myY.toString(RADIX_SEND_));
			Com.sendTo(0, myEk.toString(RADIX_SEND_));
			if (DEBUG) {
				System.out.println("DDD| (3) Bob sendet an Alice:");
				System.out.println("DDD| \t ID(Bob)         = " + myCert.getID());
				System.out.println("DDD| \t eB,nB           = " + myData.toString());
				System.out.println("DDD| \t D_T(ID,eB,nB)   = " + myCert.getSignature());
				System.out.println("DDD| \t yB              = " + myY);
				System.out.println("DDD| \t E_k(S_B(yB,yA)) = " + myEk);
			}
			//(4) nichts tun
			//(5) nichts tun
			//(6) Empfange Z(Alice),yY, Ek(S_A(yA,yB)))
			sReceive = Com.receive();
			String partnerID = sReceive;
			sReceive = Com.receive();
			BigInteger partnerEN = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerSig = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			partnerY = new BigInteger(sReceive, RADIX_SEND_);
			sReceive = Com.receive();
			BigInteger partnerCiph = new BigInteger(sReceive, RADIX_SEND_);
			if (DEBUG) {
				System.out.println("DDD| (6) Empfangen von Alice:");
				System.out.println("DDD| \t ID(Alice)         = " + partnerID);
				System.out.println("DDD| \t eAnA            = " + partnerEN);
				System.out.println("DDD| \t D_T(ID,eAnA)    = " + partnerSig);
				System.out.println("DDD| \t yA              = " + partnerY);
				System.out.println("DDD| \t E_k(S_A(yA,yB)) = " + partnerCiph);
			}
			
			//(7) Zertifikat überprüfen
			// (7)a Prüfe Zertifikat von Alice
			boolean check = checkCertificate(partnerID,partnerEN,partnerSig);
			// (7)b Prüfe S_A(yA,yB)^eA mod nA = h(yA,YB)
			hashed = computeHash(hf, partnerGamalP, partnerY, myY);
			partnerCiph = useReverseIDEA(partnerCiph,keyIdea);
			sig = partnerCiph.modPow(partnerRsaE, partnerRsaN);
			if (!sig.equals(hashed.mod(partnerRsaN))) {
				check=false;
			} else {
				if (DEBUG) System.out.println("DDD| S_A(yA,yB)^eA mod nA = h(yA,YB) erfolgreich geprüft.");
			}
			//nur weiter machen, falls es tatsächlich Alice ist
			if(check) {
			//(8) Kommunikation
				boolean communicate = true;
				while (communicate){
					String message = Com.receive();
					BigInteger code = new BigInteger(message,RADIX_SEND_);
					code = useReverseIDEA(code,keyIdea);
					
					message = BigIntToString(code);
					System.out.print("Nachricht empfangen: "+message);
					
					System.out.println("Wollen Sie antworten?");
					communicate = askYN();
					if (communicate==false) break;
					System.out.println("Schreiben Sie eine Antwort: ");
					message = askString();
					code = StringToBigInt(message);
					//System.out.println(">>>code "+code.toString(RADIX_SEND_));
					code = useIDEA(code,keyIdea);
					Com.sendTo(0, code.toString(RADIX_SEND_));
				}
			} else {
				System.err.println("Cheater!");
				System.err.println("abort game");
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private String askString() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	    String s="Tschüss bis zum nächsten Mal"; //dummymessage
	    try {
			if ((s = in.readLine()) != null && s.length() != 0){
				//nix tun, in s steht jetzt der String
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return s;
	}

	private boolean askYN() {
	    String s=askString();
	    if (s.charAt(0) == 'y'||s.charAt(0) == 'Y'){
	    	return true;
	    }
	    return false;
	}

	private BigInteger useIDEA(BigInteger message, BigInteger[] keyIdea) {
		IDEA irgendwas = new IDEA();
		BigInteger expKey[][] = irgendwas.expandKey(keyIdea);
		//System.out.println(">>>useIDEA:expKey "+expKey[0][0]+"\t"+expKey[0][1]+"\t"+expKey[0][2]+"\t"+expKey[0][3]+"\t"+expKey[1][0]+"\t"+expKey[1][1]+"\t"+expKey[1][2]+"\t"+expKey[1][3]);
		BigInteger input[][] = convertForIDEA(message);
		//System.out.println(">>>useIDEA:input "+input[0][0]+"\t"+input[0][1]+"\t"+input[0][2]+"\t"+input[0][3]+"\t"+input[1][0]+"\t"+input[1][1]+"\t"+input[1][2]+"\t"+input[1][3]);
		BigInteger output[][] = irgendwas.doEncipher(input,expKey);
		//System.out.println(">>>useIDEA:output "+output[0][0]+"\t"+output[0][1]+"\t"+output[0][2]+"\t"+output[0][3]+"\t"+output[1][0]+"\t"+output[1][1]+"\t"+output[1][2]+"\t"+output[1][3]);
		BigInteger out = convertFromIDEA(output);
		//System.out.println(">>>useIDEA:out "+out);
		return out;
	}

	private BigInteger useReverseIDEA(BigInteger code, BigInteger[] keyIdea) {
		IDEA irgendwas = new IDEA();
		BigInteger expKey[][] = irgendwas.expandKey(keyIdea);
		//System.out.println(">>>useReverseIDEA:expKey "+expKey[0][0]+"\t"+expKey[0][1]+"\t"+expKey[0][2]+"\t"+expKey[0][3]+"\t"+expKey[1][0]+"\t"+expKey[1][1]+"\t"+expKey[1][2]+"\t"+expKey[1][3]);
		BigInteger deKey[][] = irgendwas.reverseKey(expKey);
		//System.out.println(">>>useReverseIDEA:deKey "+deKey[0][0]+"\t"+deKey[0][1]+"\t"+deKey[0][2]+"\t"+deKey[0][3]+"\t"+deKey[1][0]+"\t"+deKey[1][1]+"\t"+deKey[1][2]+"\t"+deKey[1][3]);
		BigInteger input[][] = convertForIDEA(code);
		//System.out.println(">>>useReverseIDEA:input "+input[0][0]+"\t"+input[0][1]+"\t"+input[0][2]+"\t"+input[0][3]+"\t"+input[1][0]+"\t"+input[1][1]+"\t"+input[1][2]+"\t"+input[1][3]);
		BigInteger output[][] = irgendwas.doDecipher(input,deKey);
		//System.out.println(">>>useReverseIDEA:output "+output[0][0]+"\t"+output[0][1]+"\t"+output[0][2]+"\t"+output[0][3]+"\t"+output[1][0]+"\t"+output[1][1]+"\t"+output[1][2]+"\t"+output[1][3]);
		//iv wieder abschneiden
		BigInteger newout[][] = new BigInteger[output.length-1][4];
		for(int i=0;i<newout.length;i++){
			for(int j=0;j<4;j++){
				newout[i][j]=output[i+1][j];
			}
		}
		//System.out.println(">>>useReverseIDEA:newout "+newout[0][0]+"\t"+newout[0][1]+"\t"+newout[0][2]+"\t"+newout[0][3]+"\t"+newout[1][0]+"\t"+newout[1][1]+"\t"+newout[1][2]+"\t"+newout[1][3]);
		BigInteger out = convertFromIDEA(newout);
		//System.out.println(">>>useReverseIDEA:out "+out);
		return out;
	}

	private BigInteger convertFromIDEA(BigInteger[][] sig) {
		//eksig, was aus stücken der Länge 16 bit besteht, in ein riesen BigInt umwandeln
		if (sig.length < 1) {
			System.err.println("eksig zu kurz in convertFromIDEA");
			return null;
		}
		BigInteger result = BigInteger.ZERO;
		for(int i=0;i<sig.length;i++){
			for(int j=0;j<sig[i].length;j++){
				result = result.multiply(zwei.pow(16));
				if(sig[i][j]!=null){
					result = result.add(sig[i][j]);
				}
			}
		}
		return result;
	}

	private BigInteger[][] convertForIDEA(BigInteger sig) {
		// sig in BigInt der Länge 16 zerstückeln
		int bitlength = sig.bitLength();
		int reslength = (int) Math.ceil(bitlength/64.0);
		BigInteger result[][] = new BigInteger[reslength][4];
		for(int i=reslength-1;i>=0;i--){
			for(int j=3;j>=0;j--){
				result[i][j]=sig.mod(zwei.pow(16));
				sig = sig.divide(zwei.pow(16));
			}
		}
		return result;
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

	private BigInteger[] getIdeaKey(BigInteger k, int bitCount) {
		String t0 = k.toString(2);
		BigInteger keyIdea[] = new BigInteger[8];
		for(int i=0;i<8;i++){
			String t1 = t0.substring((bitCount*i)/8, (bitCount*(i+1))/8-1);
			keyIdea[i]= new BigInteger(t1,2);
		}
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
		for (int i = 0; i < mbyte.length; i++) {
			mlist.add(mbyte[i]);
		}
		BigInteger hash = hf.hashIt(mlist);

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
