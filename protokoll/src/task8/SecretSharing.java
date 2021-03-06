package task8;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

import chiffre.Grundlagen;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.Communicator;
import de.tubs.cs.iti.krypto.protokoll.Protocol;

public final class SecretSharing implements Protocol {
	// Schalter
	private final boolean DEBUG = false; // DEBUG, Allgemein
	private final boolean DEBUG_OB = false; // DEBUG für Task7 Elemente
	private final boolean DEBUG_SS = false; // DEBUG für Task8 Elemente
	private final boolean TEST = true; // für Testwerte

	private static final int RADIX_SEND_ = 2;
	private static final int SCHLEIFE_ = 0;

	private BigInteger zwei = new BigInteger("2", 10);
	private final BigInteger ZERO = new BigInteger("0");
	private final BigInteger ONE = new BigInteger("1");
	private final BigInteger TWO = new BigInteger("2");

	static private int MinPlayer = 2;
	static private int MaxPlayer = 2;
	static private String NameOfTheGame = "ObliviousTransfer";

	// ElGamal Eigene
	private BigInteger myGamalP;
	private BigInteger myGamalG;
	private BigInteger myY;
	private BigInteger myX;
	private BigInteger help;
	// ElGamal Partner
	private BigInteger partnerGamalP;
	private BigInteger partnerGamalG;
	private BigInteger partnerY;

	// Secret Sharing
	private final BigInteger WORD_MAX = new BigInteger("zzzzzzzzzz", 36);
	private BigInteger ssk; // = new BigInteger("7"); // 0...7
	private BigInteger ssn; // = new BigInteger("10"); // Geheimnispaare, max 10
	private BigInteger ssm = new BigInteger("52"); // Wortlänge (binary), max 52
													// bits
	private BigInteger ssChanceA; // Berechnungsvorteil A:B
	private BigInteger ssChanceB; // Berechnungsvorteil A:B

	private Communicator Com;
	private boolean betrug_ = false;

	public void setCommunicator(Communicator com) {
		Com = com;
	}

	public void sendFirst() {
		// (0)a Alice erzeugt sich einen ElGamal Key
		makeElGamal();
		// (0)b Alice sendet ihren PublicKey an Bob
		sendElGamal(1);
		// (0) Alice empfängt Bobs Schlüssel
		receiveElGamal();

		// (SS1) n und k für beide festlegen; k global: ssk; n global: ssn
		ssn = BigIntegerUtil.randomSmallerThan((new BigInteger("10"))).add(ONE); // 1<=n<11
		ssk = BigIntegerUtil.randomSmallerThan(new BigInteger("8")); // 0<=k<8
		if(DEBUG) {
			System.err.println("Achtung, n=1, k=2 erzwungen. Entferne diese Option.");
			ssn = BigInteger.ONE;
			ssk = (BigInteger.ONE).add(BigInteger.ONE);
		}
		// (SS1) Berechnung der Berechnungsvorteile
		setAdvantage(ssk);
		// (SS1) Bob n und k senden
		Com.sendTo(1, ssn.toString(RADIX_SEND_));
		Com.sendTo(1, ssk.toString(RADIX_SEND_));
		if (DEBUG_SS) {
			System.out.println("DDD| (SS1) Sende n und k an Bob");
			System.out.println("DDD| \t n = " + ssn.toString(RADIX_SEND_));
			System.out.println("DDD| \t k = " + ssk.toString(RADIX_SEND_));
		}

		// (SS2)a a_(i,j) mit i=1,...,n und j=1,2 erzeugen
		SecretWordSend[][] ssa = generateSecrets(ssn.intValue());
		//if (DEBUG_SS) {
			System.out.println("DDD| (SS2) Generierte Wortpaare:");
			for (int i = 0; i < ssa.length; i++) {
				System.out.print("DDD| \t ");
				System.out.print(ssa[i][0].getSecret().toString(RADIX_SEND_));
				System.out.print("\t und ");
				System.out.print(ssa[i][1].getSecret().toString(RADIX_SEND_));
				System.out.println();
			}
		//}

		// (SS3) Alice sendet Geheimnisse
		sendSecrets(1, ssa);
		// (SS3) Alice empfängt Geheimnisse
		SecretWordGuess[][] ssb = receiveSecrets(1, ssn.intValue());
		if (DEBUG_SS) {
			System.out.println("DDD| (SS3) empfangene Geheimnisse: ");
			showSecrets("DDD| \t ", ssb, RADIX_SEND_);
		}

		// (SS3) Tausche y aus
		// Solange weniger als m bits gesendet
		int sendM = ssk.intValue(); // Anzahl der in diesem Schrit versendeten
									// Bits
		int whileEnde = ssm.intValue();
		if ((SCHLEIFE_ > 0) && ((sendM + SCHLEIFE_) < whileEnde))
			whileEnde = sendM + SCHLEIFE_;
		int anzMes = (zwei.pow(ssk.intValue())).intValue(); // es werden
																// 2^{k}
																// verschiedene
																// y
																// ausgetauscht
		while (sendM < whileEnde) {
//			if(DEBUG_SS) {System.err.println(">>> Nächste Runde");}
			// Alice sagt ssa, dass sie Präfixe der Länge sendM haben will

			// Alice sendet
			// Setze die gesenderten für alle ssa zurück
			for (int i = 0; i < ssa.length; i++) {
				ssa[i][0].resetSend();
				ssa[i][1].resetSend();
			}
			// Sende nächste Runde
			for (int i = 0; i < ssa.length; i++) {
				// Alice schickt für die Hälfte der möglichen Präfixe der Länge
				// sendM die Nachricht
				// "Dieses y ist nicht das Präfix!"
				if (DEBUG_SS) {System.out.println("DDD| Alice sendet an Bob:");}				
				for (int j = 0; j < anzMes; j++) {
//					if(DEBUG_SS) {
//						System.out.println("[0]" + ssa[i][0]);
//						System.out.println("[1]" + ssa[i][1]);
//					}
					BigInteger send0 = ssa[i][0].useBinary();
					if(DEBUG_SS && send0 == null) {
						System.out.println("ssa[][0]\n" + ssa[i][0]);
					}
					if (DEBUG_SS) {System.out.println("DDD| a["+i+"][0] beginnt nicht mit "+send0.toString(RADIX_SEND_));}
					BigInteger send1 = ssa[i][1].useBinary();
					
					if(DEBUG_SS && send1 == null) {
						System.out.println("ssa[][1]\n" + ssa[i][1]);
					}
					if (DEBUG_SS) {System.out.println("DDD| a["+i+"][1] beginnt nicht mit "+send1.toString(RADIX_SEND_));}
					Com.sendTo(1,send0.toString(RADIX_SEND_));
					Com.sendTo(1,send1.toString(RADIX_SEND_));

					ssa[i][0].addSend(send0);
					ssa[i][1].addSend(send1);
				}
				// Alice empfängt für die Hälfte der möglichen Präfixe der Länge
				// sendM die Nachricht
				// "Dieses y ist nicht das Präfix"
				if (DEBUG_SS) {System.out.println("Alice empfängt von Bob:");}
				for (int j = 0; j < anzMes; j++) {
					// Alice wählt zwei y der Länge sendM
					String rec = Com.receive();
					BigInteger rec0 = new BigInteger(rec, RADIX_SEND_);
					rec = Com.receive();
					BigInteger rec1 = new BigInteger(rec, RADIX_SEND_);

					if (DEBUG_SS) {System.out.println("DDD| b["+i+"][0] beginnt nicht mit "+rec0.toString(RADIX_SEND_));}
					if (DEBUG_SS) {System.out.println("DDD| b["+i+"][1] beginnt nicht mit "+rec1.toString(RADIX_SEND_));}
					
					ssb[i][0].addReceived(rec0);
					ssb[i][1].addReceived(rec1);
				}
				// Gucken, was noch da ist
//				ssb[i][0].refreshSecrets();
//				ssb[i][1].refreshSecrets();
//				if(DEBUG_SS) System.out.println(">>>Alice benutzt refresh auf ssb.");
				
				// Erweitere die Wortlisten
				ssa[i][0].enhanceBinary(1);
				ssa[i][1].enhanceBinary(1);
				if(DEBUG_SS) {
					System.out.println(">>>Alice benutzt enhance auf ssa.");
					System.out.println(">>>ssa[0][0] ist " + ssa[0][0].toString());
					System.out.println(">>>ssb[0][0] ist " + ssb[0][0].toString());
				}
				
			}
			// Nächste Runde
			sendM = sendM + 1;
		}
		//Ermittelte Geheimnisse ausgeben
		for (int i = 0; i < ssb.length; i++){
			ssb[i][0].refreshSecrets();
			ssb[i][1].refreshSecrets();
				System.out.println("Das Geheimnis ssb["+i+"][0] ist "+ssb[i][0].getGuessedSecret().toString(RADIX_SEND_)+ "\n" + ssb[i][0].toString());
				System.out.println("Das Geheimnis ssb["+i+"][1] ist "+ssb[i][1].getGuessedSecret().toString(RADIX_SEND_)+ "\n" + ssb[i][1].toString());
		}

	}

	public void receiveFirst() {
		String sReceive;

		// (0) Bob empfängt den Public-Key von Alice
		receiveElGamal();
		// (0) Bob macht sich eigenen ElGamal Key
		makeElGamal();
		// (0) Bob sendet public Key an Partner
		sendElGamal(0);

		// (SS1) Bob empfängt n und k
		sReceive = Com.receive();
		ssn = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		ssk = new BigInteger(sReceive, RADIX_SEND_);
		setAdvantage(ssk);
		if (DEBUG_SS) {
			System.out.println("DDD| (SS1) Empfangen:");
			System.out.println("DDD| \t n = " + ssn.toString(RADIX_SEND_));
			System.out.println("DDD| \t k = " + ssk.toString(RADIX_SEND_));
		}

		// (SS2)a b_(i,j) mit i=1,...,n und j=1,2 erzeugen
		SecretWordSend[][] ssb = generateSecrets(ssn.intValue());
		//if (DEBUG_SS) {
			System.out.println("DDD| (SS2) Generierte Wortpaare:");
			for (int i = 0; i < ssb.length; i++) {
				System.out.print("DDD| \t ");
				System.out.print(ssb[i][0].getSecret().toString(RADIX_SEND_));
				System.out.print("\t und ");
				System.out.print(ssb[i][1].getSecret().toString(RADIX_SEND_));
				System.out.println();
			}
		//}

		// (SS3) Bob empfängt Nachrichten
		SecretWordGuess[][] ssa = receiveSecrets(0, ssn.intValue());
		// (SS3) Bob sendet Nachrichten
		sendSecrets(0, ssb);

		// (SS3) Tausche y aus
		// (SS3) Solange weniger als m bits gesendet
		int sendM = ssk.intValue(); // Anzahl der in diesem Schrit versendeten
									// Bits
		int whileEnde = ssm.intValue();
		if ((SCHLEIFE_ > 0) && ((sendM + SCHLEIFE_) < whileEnde))
			whileEnde = sendM + SCHLEIFE_;
		int anzMes = (zwei.pow(ssk.intValue())).intValue(); // es werden
																// 2^{k-1}
																// verschiedene
																// y
																// ausgetauscht
		while (sendM < whileEnde) {
//			if(DEBUG_SS) {System.err.println(">>> Nächste Runde");}
			// Bob empfängt
			for (int i = 0; i < ssa.length; i++) {
				// Bob empfängt für die Hälfte der möglichen Präfixe der Länge
				// sendM die Nachricht
				// "Dieses y ist nicht das Präfix"
				if(DEBUG_SS){System.out.println("DDD| Bob empfängt von Alice:");}
				for (int j = 0; j < anzMes; j++) {
					// Alice wählt zwei y der Länge sendM
					String rec = Com.receive();
					BigInteger rec0 = new BigInteger(rec, RADIX_SEND_);
					rec = Com.receive();
					BigInteger rec1 = new BigInteger(rec, RADIX_SEND_);
					
					if (DEBUG_SS) {System.out.println("DDD| a["+i+"][0] beginnt nicht mit "+rec0.toString(RADIX_SEND_));}
					if (DEBUG_SS) {System.out.println("DDD| a["+i+"][1] beginnt nicht mit "+rec1.toString(RADIX_SEND_));}

					ssa[i][0].addReceived(rec0);
					ssa[i][1].addReceived(rec1);
				}

				// Bob schickt für die Hälfte der möglichen Präfixe der Länge
				// Setze die gesenderten für alle ssa zurück
				for (int j = 0; j < ssa.length; j++) {
					ssb[j][0].resetSend();
					ssb[j][1].resetSend();
				}
				// Sende nächste Runde
				// sendM die Nachricht
				// "Dieses y ist nicht das Präfix!"
				if(DEBUG_SS){System.out.println("DDD| Bob sendet an Alice:");}
				for (int j = 0; j < anzMes; j++) {
					BigInteger send0 = ssb[i][0].useBinary();
					BigInteger send1 = ssb[i][1].useBinary();
					Com.sendTo(0, send0.toString(RADIX_SEND_));
					Com.sendTo(0, send1.toString(RADIX_SEND_));
					
					if (DEBUG_SS) {System.out.println("DDD| b["+i+"][0] beginnt nicht mit "+send0.toString(RADIX_SEND_));}
					if (DEBUG_SS) {System.out.println("DDD| b["+i+"][1] beginnt nicht mit "+send1.toString(RADIX_SEND_));}
					
					ssb[i][0].addSend(send0);
					ssb[i][1].addSend(send1);
				}
//				// Gucken, was noch da ist
//				ssa[i][0].refreshSecrets();
//				ssa[i][1].refreshSecrets();
//				if(DEBUG_SS) System.out.println(">>>Bob benutzt refresh auf ssa.");
				
				// Erweitere die Wortlisten
				ssb[i][0].enhanceBinary(1);
				ssb[i][1].enhanceBinary(1);
				if(DEBUG_SS) {
					System.out.println(">>>Bob benutzt enhance auf ssb.");
					System.out.println(">>>ssa[0][0] ist " + ssa[0][0].toString());
					System.out.println(">>>ssb[0][0] ist " + ssb[0][0].toString());
				}
			}
			// Nächste Runde
			sendM = sendM + 1;
		}
		//Ermittelte Geheimnisse ausgeben
		for (int i = 0; i < ssb.length; i++){
			ssa[i][0].refreshSecrets();
			ssa[i][1].refreshSecrets();
				System.out.println("Das Geheimnis ssa["+i+"][0] ist "+ssa[i][0].getGuessedSecret().toString(RADIX_SEND_)+ "\n" + ssb[i][0].toString());
				System.out.println("Das Geheimnis ssa["+i+"][1] ist "+ssa[i][1].getGuessedSecret().toString(RADIX_SEND_)+ "\n" + ssb[i][1].toString());
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

	private String askString() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String s = "Tschüss bis zum nächsten Mal"; // dummymessage
		try {
			if ((s = in.readLine()) != null && s.length() != 0) {
				// nix tun, in s steht jetzt der String
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return s;
	}

	// Geheimnisaustausch mit Berechnungsvorteil
	/**
	 * Generiert zufällige n Geheimnispaare
	 * 
	 * @param n
	 *            Anzahl der Geheimnispaare
	 * @return Gibt die Geheimnispaare zurück
	 */
	private SecretWordSend[][] generateSecrets(int n) {

		SecretWordSend[][] secrets = new SecretWordSend[n][2];
		BigInteger biRand;
		for (int i = 0; i < n; i++) {
			biRand = BigIntegerUtil.randomBetween(ZERO, WORD_MAX);
			secrets[i][0] = new SecretWordSend(biRand);
			secrets[i][0].startBinary(ssk.intValue());
			secrets[i][0].resetSend();

			biRand = BigIntegerUtil.randomBetween(ZERO, WORD_MAX);
			secrets[i][1] = new SecretWordSend(biRand);
			secrets[i][1].startBinary(ssk.intValue());
			secrets[i][1].resetSend();
		}

		return secrets;
	}

	/**
	 * 
	 */
	private SecretWordGuess[][] generateSecretsPartner(int n, int m) {
		SecretWordGuess[][] secrets = new SecretWordGuess[n][2];
		for (int i = 0; i < n; i++) {
			secrets[i][0] = new SecretWordGuess(ZERO, m);
			secrets[i][0].resetReceived();
			secrets[i][1] = new SecretWordGuess(ZERO, m);
			secrets[i][1].resetReceived();
		}

		return secrets;
	}

	/**
	 * Setzt den Berechnungsvorteil anhand k
	 */
	private void setAdvantage(BigInteger k) {
		ssChanceA = TWO.pow(k.intValue()).add(ONE);
		ssChanceB = TWO.pow(k.intValue());
	}

	// ElGamal
	/**
	 * 
	 */
	private void makeElGamal() {
		if (TEST) {
			myGamalP = new BigInteger(
					"13261063939096985426999424781129436987736604484071841574839029035275097976621226106248381646461633027127647215070176806960882462844165647876651836347109303");
			myGamalG = new BigInteger(
					"11449415071830494793854044177711897602839781159400329949451774490076059017229975065899539762216842867220320484076072264155276684642243703364069496832384226");
			myY = new BigInteger(
					"12291108192856071170865558012429961903760322492409283286333655332690208506622303938336813071688446187130979374752507108428801107842293004214159912505057697");
			myX = new BigInteger(
					"338247438063093584360735553456651782895945714953753136968197534452413025437614400799748890371900646240882573007655796701481099145579155445557798688838152");
			help = myGamalP.subtract(BigIntegerUtil.TWO);
		} else {
			System.out.print("A: Generiere El-Gamal Key für mich... ");
			System.out.print("Augenblick...");
			int bitLength = 512;
			BigInteger[] prime = Grundlagen.generatePrimePQ(bitLength);
			myGamalP = prime[0];
			myGamalG = Grundlagen.calcPrimeRoot(myGamalP, prime[1]);
			System.out.println("\t [OK]");
			// A wählt x zufällig in {1,...,p-2}
			help = myGamalP.subtract(BigIntegerUtil.TWO);
			myX = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			// A berechnet y = g^xA mod p
			myY = myGamalG.modPow(myX, myGamalP);
		}
	}

	/**
	 * 
	 */
	private void sendElGamal(int target) {
		Com.sendTo(target, myGamalP.toString(RADIX_SEND_)); // p
		Com.sendTo(target, myGamalG.toString(RADIX_SEND_)); // g
		Com.sendTo(target, myY.toString(RADIX_SEND_)); // yA
		if (DEBUG_OB) {
			System.out.println("DDD| (0) Sende an Partner:");
			System.out.println("DDD| \t p = " + myGamalP);
			System.out.println("DDD| \t g = " + myGamalG);
			System.out.println("DDD| (1) Sende an Partner: ");
			System.out.println("DDD| \t y = " + myY);
		}
	}

	/**
	 * 
	 */
	private void receiveElGamal() {
		String sReceive = Com.receive();
		partnerGamalP = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		partnerGamalG = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		partnerY = new BigInteger(sReceive, RADIX_SEND_);
		if (DEBUG_OB) {
			System.out.println("DDD| (0) B empfängt von A:");
			System.out.println("DDD| \t p = " + partnerGamalP);
			System.out.println("DDD| \t g = " + partnerGamalG);
			System.out.println("DDD| \t y = " + partnerY);
		}
	}

	// Senden und Empfangen nach Oblivious Transfer
	/**
	 * @param messM0
	 * @param messM1
	 */
	private void sendOblivious(int target, BigInteger messM0, BigInteger messM1) {
		// (1)a Alice wählt zufällig zwei weitere Nachrichten m1 und m2;
		BigInteger[] m = new BigInteger[2];
		m[0] = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		m[1] = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		// (1)b Alice sendet m1 und m2 an Bob
		Com.sendTo(target, m[0].toString(RADIX_SEND_)); // m1
		Com.sendTo(target, m[1].toString(RADIX_SEND_)); // m2
		if (DEBUG_OB) {
			System.out.println("DDD| (1) Senden:");
			System.out.println("DDD| \t m1 = " + m[0]);
			System.out.println("DDD| \t m2 = " + m[1]);
		}
		// (2) Alice empfängt q von Bob
		String getq = Com.receive();
		BigInteger q = new BigInteger(getq, RADIX_SEND_);
		if (DEBUG_OB) {
			System.out.println("DDD| (2) Empfangen:");
			System.out.println("DDD| \t q = " + q);
		}
		// (3)a Alice berechnet k0' und k1' und signiert sie
		// ki'=(D_A((q-m[i])mod p²))mod p
		BigInteger[] k = new BigInteger[2];
		k[0] = (q.subtract(m[0])).mod(myGamalP.multiply(myGamalP));
		k[0] = Grundlagen.elGamalDecipher(k[0], myX, myGamalP);
		k[0] = k[0].mod(myGamalP);
		k[1] = (q.subtract(m[1])).mod(myGamalP.multiply(myGamalP));
		k[1] = Grundlagen.elGamalDecipher(k[1], myX, myGamalP);
		k[1] = k[1].mod(myGamalP);
		// (3)b Alice signiert k0 und k1
		BigInteger[] Sk = new BigInteger[2];
		Sk[0] = Grundlagen.elGamalSign(k[0], myGamalP, myGamalG, myY, myX);
		Sk[1] = Grundlagen.elGamalSign(k[1], myGamalP, myGamalG, myY, myX);
		if (betrug_) {
			BigInteger i = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
			int ii = (i.mod(zwei)).intValue();
			System.out.println("DDD| Fälsche Signatur k" + ii);
			Sk[ii] = BigIntegerUtil.randomBetween(BigInteger.ONE,
					myGamalP.subtract(zwei));
		}
		if (DEBUG_OB) {
			boolean t0 = Grundlagen.elGamalVerify(k[0], Sk[0], myGamalP,
					myGamalG, myY);
			boolean t1 = Grundlagen.elGamalVerify(k[1], Sk[1], myGamalP,
					myGamalG, myY);
			System.out.println("DDD| (3)b Prüfe Signaturen:");
			System.out.println("DDD| \t Sk[0] ist " + t0);
			System.out.println("DDD| \t Sk[1] ist " + t1);
		}
		// (3)c Alice sendet beide Signaturen an Bob
		Com.sendTo(target, Sk[0].toString(RADIX_SEND_));
		Com.sendTo(target, Sk[1].toString(RADIX_SEND_));
		if (DEBUG_OB) {
			System.out.println("DDD| (3) Senden:");
			System.out.println("DDD| \t S(k0) = " + Sk[0]);
			System.out.println("DDD| \t S(k1) = " + Sk[1]);
		}
		// (3)d Alice wählt zufällig s aus {0,1}
		BigInteger sbig = BigIntegerUtil.randomBetween(BigInteger.ONE, help);
		sbig = sbig.mod(zwei);
		int s;
		// (3)e Alice berechnet (M_0+ks')mod n, (M_1+ks+1')mod n
		s = sbig.intValue(); // s
		BigInteger send0 = k[s].add(messM0).mod(myGamalP); // (M_0 + k[s]') mod
															// n
		s = sbig.xor(BigInteger.ONE).intValue(); // s xor 1
		BigInteger send1 = k[s].add(messM1).mod(myGamalP); // (M_1 + k[s+1]')
															// mod n
		// (3)f send0 und send1 beides und s an Bob senden
		Com.sendTo(target, send0.toString(RADIX_SEND_)); // send0
		Com.sendTo(target, send1.toString(RADIX_SEND_)); // send1
		Com.sendTo(target, sbig.toString(RADIX_SEND_)); // s
		if (DEBUG_OB) {
			System.out.println("DDD| (3)d-f Berechnete Werte");
			System.out.println("DDD| \t s = " + sbig);
			System.out.println("DDD| \t send0 = " + send0.toString(RADIX_SEND_));
			System.out.println("DDD| \t send1 = " + send1.toString(RADIX_SEND_));
		}

		// (4) nichts tun
	}

	/**
	 * 
	 */
	private BigInteger[] receiveAndCheckOblivious(int target) {
		String sReceive;
		// (1)b Bob empfängt m1 und m2
		String m1 = Com.receive();
		String m2 = Com.receive();
		BigInteger[] m = new BigInteger[2];
		m[0] = new BigInteger(m1, RADIX_SEND_);
		m[1] = new BigInteger(m2, RADIX_SEND_);
		if (DEBUG_OB) {
			System.out.println("DDD| (0) B empfängt von A:");
			System.out.println("DDD| \t m1 = " + m1);
			System.out.println("DDD| \t m2 = " + m2);
			System.out.println("DDD| \t m[0] = " + m[0]);
			System.out.println("DDD| \t m[1] = " + m[1]);
		}
		// (2)a Bob wählt zufällig r aus {0,1} und k aus Z_p
		BigInteger k = BigIntegerUtil.randomBetween(BigInteger.ONE,
				partnerGamalP);
		BigInteger r_z = BigIntegerUtil.randomBetween(BigInteger.ONE,
				zwei.multiply(zwei));
		int r = (r_z.mod(zwei)).intValue();
		// (2)b Bob berechnet q=(E_A(k)+m_r)mod p²
		BigInteger eak = Grundlagen.elGamalEncipher(k, partnerGamalP,
				partnerGamalG, partnerY);
		BigInteger q = (eak.add(m[r])).mod(partnerGamalP
				.multiply(partnerGamalP));
		// (2)c Bob sendet q an Alice
		Com.sendTo(target, q.toString(RADIX_SEND_));
		if (DEBUG_OB) {
			System.out.println("DDD| (2) B sendet an A:");
			System.out.println("DDD| \t r = " + r);
			System.out.println("DDD| \t q = " + q);
		}
		// (3)b Bob empfängt die Signaturen von k0' und k1' von Alice
		sReceive = Com.receive();
		BigInteger Sk0 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger Sk1 = new BigInteger(sReceive, RADIX_SEND_);
		if (DEBUG_OB) {
			System.out.println("DDD| (3) B empfängt von A:");
			System.out.println("DDD| \t Sk0 = " + Sk0);
			System.out.println("DDD| \t Sk1 = " + Sk1);
		}
		// (3)d Bob empfängt (M_0+ks')mod n, (M_1+ks+1')mod n und s von Alice
		sReceive = Com.receive();
		BigInteger rec0 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger rec1 = new BigInteger(sReceive, RADIX_SEND_);
		sReceive = Com.receive();
		BigInteger s = new BigInteger(sReceive, RADIX_SEND_);
		if (DEBUG_OB) {
			System.out.println("DDD| (3)d Bob hat empfangen");
			System.out.println("DDD| \t rec0 (send0) = " + rec0.toString(RADIX_SEND_));
			System.out.println("DDD| \t rec1 (send1) = " + rec1.toString(RADIX_SEND_));
			System.out.println("DDD| \t s = " + s.toString(RADIX_SEND_));
		}

		// (4)a Bob berechnet M_(s xor r)
		BigInteger biR = new BigInteger("" + r, 10);
		BigInteger calc;
		BigInteger calcQuer; // Das ungenutzte, andere received
		BigInteger t = biR.xor(s); // t = r xor s
		if (s.intValue() == 0 && r == 0) { // t=0
			calc = rec0; // M0 = M0 + k0
			calcQuer = rec1; // M1 = M1 + k1
		} else if (s.intValue() == 0 && r == 1) { // t=1
			calc = rec1; // M1 = M1 + k1
			calcQuer = rec0; // M0 = M0 + k0
		} else if (s.intValue() == 1 && r == 1) { // t=0
			calc = rec0; // M0 = M0 + k1
			calcQuer = rec1; // M1 = M1 + k0
		} else { // t=1
			calc = rec1; // M1 = M1+k0
			calcQuer = rec0; // M0 = M0 + k1
		}
		// M_(s xor r)
		calc = calc.mod(partnerGamalP);
		calc = calc.subtract(k); // sendT - k
		calc = calc.mod(partnerGamalP); // sendT - k mod p

		// kQuer_(r xor 1) = (calcQuer mod p - calc) mod p
		BigInteger kQuer;
		kQuer = calcQuer.mod(partnerGamalP);
		kQuer = kQuer.subtract(calc);
		kQuer = kQuer.mod(partnerGamalP);

		BigInteger test = calcQuer.mod(partnerGamalP);
		test = test.subtract(k);
		test = test.mod(partnerGamalP);

		if (DEBUG_OB) {
			System.out.println("DDD| (4)a Bob berechnet M_(s xor r)");
			System.out
					.println("DDD| \t s xor r = " + s + " xor " + r + "=" + t);
			System.out.println("DDD| \t M_(s xor r) = " + calc);
			System.out.println("DDD| \t M_(s xor r) = " + calc.toString(36));
			System.out.println("DDD| \t Test = " + test);
			System.out.println("DDD| \t Test = " + test.toString(36));
		}

		// (4)b Bob prüft, ob Alice betrogen hat
		boolean checkCheat = false;
		// (4)b Prüfe, ob Signaturen für k und/oder kQuer gelten
		boolean s0OK = Grundlagen.elGamalVerify(k, Sk0, partnerGamalP,
				partnerGamalG, partnerY);
		boolean s1OK = Grundlagen.elGamalVerify(k, Sk1, partnerGamalP,
				partnerGamalG, partnerY);
		boolean sQ0OK = Grundlagen.elGamalVerify(kQuer, Sk0, partnerGamalP,
				partnerGamalG, partnerY);
		boolean sQ1OK = Grundlagen.elGamalVerify(kQuer, Sk1, partnerGamalP,
				partnerGamalG, partnerY);
		if (DEBUG_OB) {
			System.out.println("DDD| (4)b Prüfe gültige Siganturen");
			System.out.println("DDD| \t k  : " + s0OK + " \t " + s1OK);
			System.out.println("DDD| \t kQ : " + sQ0OK + " \t " + sQ1OK);
		}

		if (DEBUG_OB) {
			System.out.println("DDD| (4)b BETRUGSVERSUCHE:");
		}
		// (4)b Signatur auf k ist falsch
		boolean cheat1;
		cheat1 = !(s0OK ^ s1OK);
		// (4)b Signatur gilt für beide k
		boolean cheat2;
		cheat2 = ((s0OK && sQ0OK) || (s1OK && sQ1OK));
		// (4)b Sk0=Sk1, identische Signaturen
		boolean cheat3;
		cheat3 = Sk0.equals(Sk1);
		// (4)b EA(kQuer(rxor1)) = (q-m(rxor1)) mod p
		boolean cheat4;
		BigInteger eQuer;
		BigInteger qQuer;
		eQuer = Grundlagen.elGamalEncipher(kQuer, partnerGamalP, partnerGamalG,
				partnerY);
		qQuer = q.subtract(m[biR.xor(BigInteger.ONE).intValue()]).mod(
				partnerGamalP);
		cheat4 = eQuer.equals(qQuer);
		if (DEBUG_OB) {
			System.out.println("DDD| \t s(k) gilt nicht für k     : " + cheat1);
			System.out.println("DDD| \t s(k) gilt für k und kQ    : " + cheat2);
			System.out.println("DDD| \t s(k0)==s(k1)              : " + cheat3);
			System.out.println("DDD| \t EA(kQ)==(q-m)mod n        : " + cheat4);
		}

		checkCheat = cheat1 || cheat2 || cheat3 || cheat4;
		if (checkCheat) { // Betrüger
			return null;
		} else { // Ehrlich
			BigInteger[] back = new BigInteger[2];
			back[0] = calc;
			back[1] = biR.xor(s);
			return back;
		}
	}

	/**
	 * @param secrets
	 */
	private void sendSecrets(int target, SecretWordSend[][] secrets) {
		for (int i = 0; i < secrets.length; i++) {
			BigInteger send0 = secrets[i][0].getSecret();
			BigInteger send1 = secrets[i][1].getSecret();
			sendOblivious(target, send0, send1);
		}
	}

	/**
	 * @param ssb
	 * @return
	 */
	private SecretWordGuess[][] receiveSecrets(int target, int n) {
		SecretWordGuess[][] ssa = generateSecretsPartner(n,ssm.intValue());
		for (int i = 0; i < n; i++) {
			BigInteger[] rec = receiveAndCheckOblivious(target);
			ssa[i][rec[1].intValue()] = new SecretWordGuess(rec[0], ssm.intValue());
			ssa[i][rec[1].xor(ONE).intValue()] = new SecretWordGuess(ZERO,ssm.intValue());
		}
		return ssa;
	}

	/**
	 * Gibt die SecretWords als Text aus. Format: Prefix SecretWord1 \t
	 * (SecretGuessedWord1) \t\t SecretWord2 \t (SecretGuessedWort2)
	 * 
	 * @param pre
	 *            Zeilenbeginn
	 * @param secrets
	 *            Die Geheimnisse
	 * @param rad
	 *            Radix, in welcher die Geheimnisse angezeigt werden sollen
	 */
	private void showSecrets(String pre, SecretWord[][] secrets, int rad) {
		for (int i = 0; i < secrets.length; i++) {
			System.out.print(pre);
			System.out.print(secrets[i][0].getSecret().toString(rad));
			System.out.print("\t");
			System.out.print("("
					+ secrets[i][0].getGuessedSecret().toString(rad) + ")");
			System.out.print("\t\t");
			System.out.print(secrets[i][1].getSecret().toString(rad));
			System.out.print("\t");
			System.out.print("("
					+ secrets[i][1].getGuessedSecret().toString(rad) + ")");
			System.out.println();
		}
	}

}
