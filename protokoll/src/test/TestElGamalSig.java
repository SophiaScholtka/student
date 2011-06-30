package test;

import java.math.BigInteger;

import chiffre.Grundlagen;

public class TestElGamalSig {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		BigInteger pubP = new BigInteger("13261063939096985426999424781129436987736604484071841574839029035275097976621226106248381646461633027127647215070176806960882462844165647876651836347109303");
		BigInteger pubG = new BigInteger("11449415071830494793854044177711897602839781159400329949451774490076059017229975065899539762216842867220320484076072264155276684642243703364069496832384226");
		BigInteger pubY = new BigInteger("12291108192856071170865558012429961903760322492409283286333655332690208506622303938336813071688446187130979374752507108428801107842293004214159912505057697");
		BigInteger priX = new BigInteger("338247438063093584360735553456651782895945714953753136968197534452413025437614400799748890371900646240882573007655796701481099145579155445557798688838152");
		BigInteger mess = new BigInteger("hallo",36);
		BigInteger messF = mess.flipBit(2);
		
		// Teste richtige Nachricht zur Signatur
		BigInteger sig = Grundlagen.elGamalSignOld(mess, pubP, pubG, pubY, priX);
		boolean veri = Grundlagen.elGamalVerifyOld(mess, sig, pubP, pubG, pubY);
		if(veri == true) {
			System.out.println("ALT> Richtige Nachricht zur Signatur: erfolgreich");
		} else {
			System.out.println("ALT> Richtige Nachricht zur Signatur: fehlgeschlagen");
		}
		

		// Teste richtige Nachricht zur Signatur
		BigInteger sig2 = Grundlagen.elGamalSign(mess, pubP, pubG, pubY, priX);
		boolean veri2 = Grundlagen.elGamalVerify(mess, sig2, pubP, pubG, pubY);
		if(veri2 == true) {
			System.out.println("---> Richtige Nachricht zur Signatur: erfolgreich");
		} else {
			System.out.println("---> Richtige Nachricht zur Signatur: fehlgeschlagen");
		}
		

		// Teste falsche Nachricht zur Signatur		
		BigInteger sig3 = Grundlagen.elGamalSignOld(mess, pubP, pubG, pubY, priX);
		boolean veri3 = Grundlagen.elGamalVerifyOld(messF, sig3, pubP, pubG, pubY);
		if(veri3 == true) {
			System.out.println("ALT> Falsche Nachricht zur Signatur: erfolgreich");
		} else {
			System.out.println("ALT> Falsche Nachricht zur Signatur: fehlgeschlagen");
		}
		
		BigInteger sig4 = Grundlagen.elGamalSign(mess, pubP, pubG, pubY, priX);
		boolean veri4 = Grundlagen.elGamalVerify(messF, sig4, pubP, pubG, pubY);
		if(veri4 == true) {
			System.out.println("---> Falsche Nachricht zur Signatur: erfolgreich");
		} else {
			System.out.println("---> Falsche Nachricht zur Signatur: fehlgeschlagen");
		}
		
		// Teste richtige Nachricht zur falschen Signatur
		BigInteger sig5 = Grundlagen.elGamalSignOld(mess, pubP, pubG, pubY, priX);
		boolean veri5 = Grundlagen.elGamalVerifyOld(mess, sig5.flipBit(2), pubP, pubG, pubY);
		if(veri5 == true) {
			System.out.println("ALT> Richtige Nachricht zur falschen Signatur: erfolgreich");
		} else {
			System.out.println("ALT> Richtige Nachricht zur falschen Signatur: fehlgeschlagen");
		}
		
		BigInteger sig6 = Grundlagen.elGamalSign(mess, pubP, pubG, pubY, priX);
		boolean veri6 = Grundlagen.elGamalVerify(mess, sig6.flipBit(2), pubP, pubG, pubY);
		if(veri6 == true) {
			System.out.println("---> Richtige Nachricht zur falschen Signatur: erfolgreich");
		} else {
			System.out.println("---> Richtige Nachricht zur falschen Signatur: fehlgeschlagen");
		}
		
		// Teste falsche Nachricht zur falschen Signatur
		BigInteger sig7 = Grundlagen.elGamalSignOld(mess, pubP, pubG, pubY, priX);
		boolean veri7 = Grundlagen.elGamalVerifyOld(messF, sig7.flipBit(2), pubP, pubG, pubY);
		if(veri7 == true) {
			System.out.println("ALT> Falsche Nachricht zur falschen Signatur: erfolgreich");
		} else {
			System.out.println("ALT> Falsche Nachricht zur falschen Signatur: fehlgeschlagen");
		}
		
		BigInteger sig8 = Grundlagen.elGamalSign(mess, pubP, pubG, pubY, priX);
		boolean veri8 = Grundlagen.elGamalVerify(messF, sig8.flipBit(2), pubP, pubG, pubY);
		if(veri8 == true) {
			System.out.println("---> Falsche Nachricht zur falschen Signatur: erfolgreich");
		} else {
			System.out.println("---> Falsche Nachricht zur falschen Signatur: fehlgeschlagen");
		}
	}

}
