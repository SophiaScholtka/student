package task7;
import de.tubs.cs.iti.krypto.protokoll.*;
public final class ObliviousTransfer implements Protocol {
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
		//(0)a Alice erzeugt sich einen ElGamal Key
		//(0)b Alice sendet ihren PublicKey an Bob
		//(0)c Alice gibt zwei Nachrichten M1 und M2 an, von denen Bob eine erhalten soll
		String M1 = "Geheimnis1   ";
		String M2 = "Geheimnis2   ";
		//(1)a Alice wählt zufällig zwei weitere Nachrichten m1 und m2;
		String m1 = "ashdfö";
		String m2 = "oishga";
		//(1)b Alice sendet m1 und m2 an Bob
		//(2) Alice empfängt q von Bob
		//(3)a Alice berechnet k0' und k1' und signiert sie
		//(3)b Alice sendet beide Signaturen an Bob
		//(3)c Alice wählt zufällig s aus {0,1}
		//(3)d Alice berechnet (M_0+ks')mod n, (M_1+ks+1')mod n und sendet beides und s an Bob
		//(4) nichts tun
	}
	
	public void receiveFirst ()
	{
		//(0) Bob empfängt den Public-Key von Alice
		//(1)b Bob empfängt m1 und m2
		String m1 = "ashdfö";
		String m2 = "oishga";
		//(2)a Bob wählt zufällig r aus {0,1} und k aus Z_n
		//(2)b Bob berechnet q=(E_A(k)+m_r)mod n
		//(2)c Bob sendet q an Alice
		//(3)b Bob empfängt die Signaturen von k0' und k1' von Alice
		//(3)d Bob empfängt (M_0+ks')mod n, (M_1+ks+1')mod n und s von Alice
		//(4)a Bob berechnet M_s+r
		//(4)b Bob prüft, ob Alice betrogen hat

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
}
