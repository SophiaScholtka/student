package task9;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;

public class Erklaerung {
	private static String sEnter = "" + (char) 13 + (char) 10;
	private static String sApo = "" + (char) 34;
	private static String sIn = "" + (char) 8712;

	
	/**
	 * Addiert einen byte-Array auf zu einem einzigen BigInteger
	 * @param bytes
	 * @return
	 */
	public static BigInteger changeBytesToBig(byte[] bytes) {
		BigInteger big = new BigInteger("0");
		for (int i = 0; i < bytes.length; i++) {
			BigInteger addBig = new BigInteger("" + bytes[i]);
			big.add(addBig);
		}
		
		return big;
	}
	public static byte[] changeBigsToByte(BigInteger[] bigs) {
		int mod = 8;
		
		ArrayList<Byte> bytes = new ArrayList<Byte>();
		
		// Zerhacke bigints in bytes
		for (int i = 0; i < bigs.length; i++) {
			String s = bigs[i].toString(2);
			while (s.length() % mod != 0) {
				s = "0" + s;
			}
			
			String sBig = "";
			for (int i1 = 0; i1 < s.length() ; i1++) {
				sBig = sBig + s.charAt(i1);
				if (sBig.length() == mod) {
					System.out.println("neue Zahl: " + sBig);
					BigInteger big = new BigInteger(sBig,2);
					bytes.add(big.byteValue());
					sBig = "";
				}
			}
		}
		
		// liste zu array
		byte[] back = new byte[bytes.size()];
		int index = 0;
		for (Iterator<Byte> it = bytes.iterator(); it.hasNext();) {
			Byte byte1 = (Byte) it.next();
			back[index] = byte1;
			index++;
		}
		
		return back;
	}
	
	public static byte[] createStateBytes(String myName, String partnerName,
			BigInteger[] vertrag, int n, int amount) throws ParseException {
		
		BigInteger[] stateContract;
		stateContract = createStateContract(myName, partnerName,vertrag,n, amount);
		
		return changeBigsToByte(stateContract);
	}
	
	public static BigInteger[] createStateContract(String myName, String partnerName,
			BigInteger[] vertrag, int n, int amount) {
		if (amount < 1) {
			amount = 1;
		}
		
		String statement = generateStatement(myName, partnerName, n);
		ArrayList<BigInteger> whole = new ArrayList<BigInteger>();

		// Statement to List
		whole.addAll(changeStringToList(statement,amount));
		
		// add contract
		for (int i = 0; i < vertrag.length; i++) {
			whole.add(vertrag[i]);
		}

		// List to Array
		BigInteger[] back = new BigInteger[whole.size()];
		for (int i = 0; i < whole.size(); i++) {
			back[i] = whole.get(i);
		}

		return back;
	}

	public static String generateStatement(String myName, String partnerName, int n) {
		String erk = "";
		erk = sApo;
		erk += "Die Symbole ";
		erk += getSub(myName + "'", "i,j");
		erk += " bezeichnen Lösungen der zugehörigen S-Puzzles ";
		erk += getSub("C", getSub(myName, "i,j"));
		erk += ", i " + sIn + " {1,...," + n + "}, j " + sIn + " {1,2}.";

		erk += " Der untenstehende Vertrag ist von mir unterzeichnet, wenn ";
		erk += partnerName;
		erk += " für ein i " + sIn + " {1,...," + n + "} die beiden Schlüssel ";
		erk += getSub(myName + "'", "i,1");
		erk += " und ";
		erk += getSub(myName + "'", "i,2");
		erk += " nennen kann, d. h. wenn er";
		erk += " die Lösung des (i,1)-ten und (i,2)-ten Puzzles kennt.";

		erk = erk + sApo;
		return erk;
	}

	private static String getSub(String top, String down) {
		return top + "_{" + down + "}";
	}
	
	public static ArrayList<BigInteger> changeStringToList(String string, int amount) {
		ArrayList<BigInteger> whole = new ArrayList<BigInteger>();
		
		int index = 0;
		while (index < string.length()){
			BigInteger big = new BigInteger("" + (int)string.charAt(index));
			index++;
			for (int j = 1; j < amount; j++) {
				big = big.shiftLeft(8);
				
				BigInteger bigT;
				if (index < string.length()) {
					bigT = new BigInteger("" + (int)string.charAt(index));
				} else {
					bigT = new BigInteger("" + (int) ' ');
				}
				big = big.add(bigT);
				index++;
			}
			whole.add(big);
		}
		return whole;
	}
}
