package task7;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

import chiffre.Grundlagen;
import task6.StationToStation;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;
public final class ObliviousTransfer implements Protocol {
	private final boolean DEBUG = true;

	private static final int RADIX_SEND_ = 16;
	private BigInteger zwei = new BigInteger("2",10);
	
	static private int MinPlayer        = 2;
	static private int MaxPlayer        = 2;
	static private String NameOfTheGame = "ObliviousTransfer";

    private Communicator Com;
	
	public void setCommunicator(Communicator com)
	{
	  Com = com;
	}
	
	
	public void sendFirst ()
	{
		//TODO User fragen, ob und wo Alice betrügen soll
		
		//(0)a Alice erzeugt sich einen ElGamal Key
		System.out.print("A: Generiere El-Gamal Key für mich... "
				+ "Augenblick...");
		int bitLength = 512;
		BigInteger[] prime = Grundlagen.generatePrimePQ(bitLength);
		BigInteger myGamalP = prime[0];
		BigInteger myGamalG = Grundlagen.calcPrimeRoot(myGamalP, prime[1]);
		System.out.println("\t [OK]");
		//A wählt x zufällig in {1,...,p-2}
		BigInteger help = myGamalP.subtract(BigIntegerUtil.TWO);
		BigInteger myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		//A berechnet y = g^xA mod p
		BigInteger myY = myGamalG.modPow(myX, myGamalP);
		
		//(0)b Alice sendet ihren PublicKey an Bob
		Com.sendTo(1, myGamalP.toString(RADIX_SEND_)); // p
		Com.sendTo(1, myGamalG.toString(RADIX_SEND_)); // g
		Com.sendTo(1, myY.toString(RADIX_SEND_)); // yA
		if (DEBUG) {
			System.out.println("DDD| (0) A sendet an B:");
			System.out.println("DDD| \t p = " + myGamalP);
			System.out.println("DDD| \t g = " + myGamalG);
			System.out.println("DDD| (1) A sendet yA an B: " + myY);
		}
		
		//(0)c Alice gibt zwei Nachrichten M1 und M2 an, von denen Bob eine erhalten soll
		System.out.println("Geben sie jetzt die beiden Nachrichten an, von denen Bob eine erhalten soll.");
		System.out.println("Nachricht 1: ");
		String M0 = askString();
		BigInteger messM0 = new BigInteger(M0,36);
		System.out.println("Nachricht 2: ");
		String M1 = askString();
		BigInteger messM1 = new BigInteger(M1,36);
		
		if(DEBUG) {
			System.out.println("DDD| (0)c Alice Nachrichten");
			System.out.println("DDD| \t Nachricht 1: " + M0);
			System.out.println("DDD| \t Nachricht 1: " + messM0);
			System.out.println("DDD| \t Nachricht 1: " + messM0.toString(36));
			System.out.println("DDD| \t Nachricht 2: " + M1);
			System.out.println("DDD| \t Nachricht 2: " + messM1);
			System.out.println("DDD| \t Nachricht 2: " + messM1.toString(36));
		}
		
		//(1)a Alice wählt zufällig zwei weitere Nachrichten m1 und m2;
		BigInteger mess1 = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		String m1 = mess1.toString(36);//radix 36 damit auch viele Buchstaben raus kommen
		BigInteger mess2 = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		String m2 = mess2.toString(36);
		BigInteger[] m = new BigInteger[2];
		m[0]= mess1;
		m[1]= mess2;
		//(1)b Alice sendet m1 und m2 an Bob
		Com.sendTo(1, m1); // m1
		Com.sendTo(1, m2); // m2
		if (DEBUG) {
			System.out.println("DDD| (1) A sendet an B:");
			System.out.println("DDD| \t m1 = " + m1);
			System.out.println("DDD| \t m2 = " + m2);
		}
		//(2) Alice empfängt q von Bob
		String getq = Com.receive();
		BigInteger q = new BigInteger(getq,RADIX_SEND_);
		if(DEBUG){
			System.out.println("DDD| (2) A empfängt von B");
			System.out.println("DDD| \t q = " + q);
		}
		//(3)a Alice berechnet k0' und k1' und signiert sie
		//ki'=(D_A((q-m[i])mod p²))mod p
		BigInteger[] k = new BigInteger[2];
		k[0] = (q.subtract(m[0])).mod(myGamalP.multiply(myGamalP));
		k[0] = Grundlagen.elGamalDecipher(k[0], myX, myGamalP);
		k[0] = k[0].mod(myGamalP);
		k[1] = (q.subtract(m[1])).mod(myGamalP.multiply(myGamalP));
		k[1] = Grundlagen.elGamalDecipher(k[1], myX, myGamalP);
		k[1] = k[1].mod(myGamalP);
		//(3)b Alice signiert k0 und k1
		BigInteger[] Sk = new BigInteger[2];
		Sk[0] = Grundlagen.elGamalSign(k[0], myGamalP, myGamalG, myY, myX);
		Sk[1] = Grundlagen.elGamalSign(k[1], myGamalP, myGamalG, myY, myX);
		//(3)c Alice sendet beide Signaturen an Bob
		Com.sendTo(1, Sk[0].toString(RADIX_SEND_));
		Com.sendTo(1, Sk[1].toString(RADIX_SEND_));
		if (DEBUG) {
			System.out.println("DDD| (3) A sendet an B:");
			System.out.println("DDD| \t S(k0) = " + Sk[0]);
			System.out.println("DDD| \t S(k1) = " + Sk[1]);
		}
		//(3)d Alice wählt zufällig s aus {0,1}
		BigInteger sbig = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		sbig = sbig.mod(zwei);
		int s;
		//(3)e Alice berechnet (M_0+ks')mod n, (M_1+ks+1')mod n
		s = sbig.intValue(); // s
		BigInteger send0 = k[s].add(messM0).mod(myGamalP); // (M_0 + k[s]') mod n
		s = sbig.xor(BigInteger.ONE).intValue(); // s xor 1
		BigInteger send1 = k[s].add(messM1).mod(myGamalP); // (M_1 + k[s+1]') mod n
		//(3)f send0 und send1 beides und s an Bob senden
		Com.sendTo(1,send0.toString(RADIX_SEND_)); // send0
		Com.sendTo(1,send1.toString(RADIX_SEND_)); // send1
		Com.sendTo(1, sbig.toString(RADIX_SEND_)); // s
		if (DEBUG) {
			System.out.println("DDD| (3)d-f Berechnete Werte");
			System.out.println("DDD| \t s = " + sbig);
			System.out.println("DDD| \t send0 = " + send0.toString(16));
			System.out.println("DDD| \t send1 = " + send1.toString(16));
		}
		
		//(4) nichts tun
	}
	
	public void receiveFirst ()
	{
		//(0) Bob empfängt den Public-Key von Alice
		String sReceive = Com.receive();
		BigInteger partnerGamalP = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger partnerGamalG = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger partnerY = new BigInteger(sReceive, RADIX_SEND_);
		if (DEBUG) {
			System.out.println("DDD| (0) B empfängt von A:");
			System.out.println("DDD| \t p = " + partnerGamalP);
			System.out.println("DDD| \t g = " + partnerGamalG);
			System.out.println("DDD| \t y = " + partnerY);
		}
		//(1)b Bob empfängt m1 und m2
		String m1 = Com.receive();
		String m2 = Com.receive();
		if (DEBUG) {
			System.out.println("DDD| (0) B empfängt von A:");
			System.out.println("DDD| \t m1 = " + m1);
			System.out.println("DDD| \t m2 = " + m2);
		}
		BigInteger[] m = new BigInteger[2];
		byte[] t1 = m1.getBytes();
		m[0]= new BigInteger(t1);
		byte[] t2 = m2.getBytes();
		m[1]= new BigInteger(t2);
		//(2)a Bob wählt zufällig r aus {0,1} und k aus Z_p
		BigInteger k = BigIntegerUtil.randomBetween(BigInteger.ONE, partnerGamalP);
		BigInteger r_z = BigIntegerUtil.randomBetween(BigInteger.ONE, zwei.multiply(zwei));
		int r = (r_z.mod(zwei)).intValue();
		//(2)b Bob berechnet q=(E_A(k)+m_r)mod p²
		BigInteger eak = Grundlagen.elGamalEncipher(k, partnerGamalP, partnerGamalG, partnerY);
		BigInteger q = (eak.add(m[r])).mod(partnerGamalP.multiply(partnerGamalP)) ;
		//(2)c Bob sendet q an Alice
		Com.sendTo(0, q.toString(RADIX_SEND_));
		if (DEBUG) {
			System.out.println("DDD| (2) B sendet an A:");
			System.out.println("DDD| \t r = " + r);
			System.out.println("DDD| \t q = " + q);
		}
		//(3)b Bob empfängt die Signaturen von k0' und k1' von Alice
		sReceive = Com.receive();
		BigInteger Sk0 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger Sk1 = new BigInteger(sReceive, RADIX_SEND_);
		if (DEBUG) {
			System.out.println("DDD| (3) B empfängt von A:");
			System.out.println("DDD| \t Sk0 = " + Sk0);
			System.out.println("DDD| \t Sk1 = " + Sk1);
		}
		//(3)d Bob empfängt (M_0+ks')mod n, (M_1+ks+1')mod n und s von Alice
		sReceive = Com.receive();
		BigInteger rec0 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger rec1 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger s = new BigInteger(sReceive, RADIX_SEND_);
		if(DEBUG) {
			System.out.println("DDD| (3)d Bob hat empfangen");
			System.out.println("DDD| \t rec0 (send0) = " + rec0.toString(16));
			System.out.println("DDD| \t rec1 (send1) = " + rec1.toString(16));
			System.out.println("DDD| \t s = " + s.toString(16));
		}
		
		//(4)a Bob berechnet M_(s xor r)
		BigInteger biR = new BigInteger(""+r,10);
		BigInteger calc;
		BigInteger calcQuer; // Das ungenutzte, andere received
		BigInteger t = biR.xor(s); // t = r xor s
		if (t.intValue() == 0 && s.intValue() == 0 && r == 0) {
			calc = rec0; // M0 = M0 + k0
			calcQuer = rec1; // M1 = M1 + k1
		}
		else if (t.intValue() == 1 && s.intValue() == 0 && r == 1) {
			calc = rec1; // M1 = M1 + k1
			calcQuer = rec0; // M0 = M0 + k0
		}
		else if (t.intValue() == 0 && s.intValue() == 1 && r == 1) {
			calc = rec0; // M0 = M0 + k1
			calcQuer = rec1; // M1 = M1 + k0
		} 
		else {
			calc = rec1; // M1 = M1+k0
			calcQuer = rec0; // M0 = M0 + k1
		}
		// M_(s xor r)
		calc = calc.subtract(k); // sendT - k
		calc = calc.mod(partnerGamalP); // sendT - k mod p
		
		// kQuer_(r xor 1) = (calcQuer mod p - calc) mod p
		BigInteger kQuer = calcQuer.mod(partnerGamalP);
		kQuer = kQuer.subtract(calc);
		kQuer = kQuer.mod(partnerGamalP);
		
		if(DEBUG) { 
			System.out.println("DDD| (4)a Bob berechnet M_(s xor r)");
			System.out.println("DDD| \t s xor r = " + s + " xor " + r + "=" + t);
			System.out.println("DDD| \t M_(s xor r) = " + calc);
			System.out.println("DDD| \t M_(s xor r) = " + calc.toString(36));
		}
		
		//(4)b Bob prüft, ob Alice betrogen hat
		// FIXME Fehlerquelle - was ist genau kQuer?
		boolean checkCheat = false;
		if (biR.xor(BigInteger.ONE).equals(BigInteger.ZERO)) { // r xor 1 = 0
			checkCheat = Grundlagen.elGamalVerify(kQuer, Sk0, partnerGamalP, partnerGamalP, partnerY);
		} else { // r xor 1 = 1
			checkCheat = Grundlagen.elGamalVerify(kQuer, Sk1, partnerGamalP, partnerGamalP, partnerY);
		}
		
		if(!checkCheat) {
			System.out.println("Kein Betrug von Alice festgestellt.");
			System.out.println("Nachricht: " + calc.toString(36));
		} else {
			System.out.println("Betrüger!");
			System.out.println("\t ( kQuer_(r xor 1) == k'_(r xor 1) identisch, daher auch M0 == M1 )");
		}

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
	
	private String askString() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	    String s="Tschüss bis zum nächsten Mal"; //dummymessage
	    try {
			if ((s = in.readLine()) != null && s.length() != 0){
				//nix tun, in s steht jetzt der String
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return s;
	}
}
