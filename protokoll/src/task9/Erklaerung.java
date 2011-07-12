package task9;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

public class Erklaerung {
	private static String sEnter = "" + (char) 13 + (char) 10;
	private static String sApo = "" + (char) 34;
	private static String sIn = "" + (char) 8712;

	/**
	 * Verbindet Erkärung und Vertrag zu einem Ganzen
	 * @param statement Erklärung
	 * @param contract Vertrag
	 * @return Erklärung+Vertrag
	 */
	public static BigInteger[] createStateContract(BigInteger[] statement,
			BigInteger[] contract) {

		ArrayList<BigInteger> whole = new ArrayList<BigInteger>();

		// Statement to list
		ArrayList<BigInteger> stateList;
		stateList = Erklaerung.changeToList(statement);

		// Contract to list
		ArrayList<BigInteger> contractList;
		contractList = Erklaerung.changeToList(contract);

		// Combine statement and contract
		whole.addAll(stateList);
		whole.addAll(contractList);

		// List to Array
		BigInteger[] back = new BigInteger[whole.size()];
		for (int i = 0; i < whole.size(); i++) {
			back[i] = whole.get(i);
		}

		return back;
	}

	/**
	 * Erzeugt die Erklärung
	 * @param myName Eigener Name
	 * @param partnerName Name des Partners
	 * @param n Anzahl der Geheimnisse
	 * @return String mit der erzeugten Erklärung
	 */
	public static String generateStatement(String myName, String partnerName,
			int n) {
		String erk = "";
		erk = sApo;
		erk += "Die Symbole ";
		erk += writeSubstring(myName + "'", "i,j");
		erk += " bezeichnen Lösungen der zugehörigen S-Puzzles ";
		erk += writeSubstring("C", writeSubstring(myName, "i,j"));
		erk += ", i " + sIn + " {1,...," + n + "}, j " + sIn + " {1,2}.";

		erk += " Der untenstehende Vertrag ist von mir unterzeichnet, wenn ";
		erk += partnerName;
		erk += " für ein i " + sIn + " {1,...," + n + "} die beiden Schlüssel ";
		erk += writeSubstring(myName + "'", "i,1");
		erk += " und ";
		erk += writeSubstring(myName + "'", "i,2");
		erk += " nennen kann, d. h. wenn er";
		erk += " die Lösung des (i,1)-ten und (i,2)-ten Puzzles kennt.";

		erk = erk + sApo;
		return erk;
	}

	private static String writeSubstring(String top, String down) {
		return top + "_{" + down + "}";
	}

	public static BigInteger[] changeToBigs(String string, int amount) {
		ArrayList<BigInteger> bigList = changeToList(string, amount);

		BigInteger[] bigs = new BigInteger[bigList.size()];
		int index = 0;
		for (Iterator<BigInteger> it = bigList.iterator(); it.hasNext();) {
			BigInteger big = (BigInteger) it.next();
			bigs[index] = big;
			index++;
		}
		return bigs;
	}

	/**
	 * Addiert einen byte-Array auf zu einem einzigen BigInteger
	 * 
	 * @param bytes
	 * @return
	 */
	public static BigInteger changeToBig(byte[] bytes) {
		BigInteger big = new BigInteger("0");
		for (int i = 0; i < bytes.length; i++) {
			BigInteger addBig = new BigInteger("" + bytes[i]);
			big.add(addBig);
		}
	
		return big;
	}

	public static byte[] changeToBytes(BigInteger[] bigs) {
		int mod = 8;
	
		ArrayList<Byte> bytes = new ArrayList<Byte>();
	
		// Zerhacke bigints in bytes
		for (int i = 0; i < bigs.length; i++) {
			String s = bigs[i].toString(2);
			while (s.length() % mod != 0) {
				s = "0" + s;
			}
	
			String sBig = "";
			for (int i1 = 0; i1 < s.length(); i1++) {
				sBig = sBig + s.charAt(i1);
				if (sBig.length() == mod) {
					BigInteger big = new BigInteger(sBig, 2);
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

	public static ArrayList<BigInteger> changeToList(String string, int amount) {
		ArrayList<BigInteger> whole = new ArrayList<BigInteger>();
	
		int index = 0;
		while (index < string.length()) {
			BigInteger big = new BigInteger("" + (int) string.charAt(index));
			index++;
			for (int j = 1; j < amount; j++) {
				big = big.shiftLeft(8);
	
				BigInteger bigT;
				if (index < string.length()) {
					bigT = new BigInteger("" + (int) string.charAt(index));
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

	public static ArrayList<BigInteger> changeToList(BigInteger[] bigs) {
	
		ArrayList<BigInteger> list = new ArrayList<BigInteger>();
		for (int i = 0; i < bigs.length; i++) {
			list.add(bigs[i]);
		}
		return list;
	}

	public static String changeToString(BigInteger[] bigs) {
		String s = "";
		for (int i = 0; i < bigs.length; i++) {
			s = s + (char) bigs[i].intValue();
		}

		return s;
	}
}
