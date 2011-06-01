/*
 * Created on 05.05.2003
 *
 * This Code was initially written by Lars Girndt
 */
package de.tubs.cs.iti.krypto.protokoll;

/**
 * Diese Klasse stellt mit einem Kommandozeilenclient eine Alternative
 * zu der Framevariante Client bereit. Sie wurde geschaffen, um das 
 * Entwickeln von Protokollen für das Kryptologie-Praktikum zu unterstützen.
 * <p>
 * Diese Einschränkung sorgt somit dafür, dass hier nur Protokolle mit einer
 * Teilnehmerzahl von 2 ausgeführt werden können.
 * <p>
 * Bitte folgendes durchführen, um entsprechendes Protokoll zu testen
 * <ol>
 * <li>Server starten mit
<pre>
java de.tubs.cs.iti.krypto.protokoll.Server
</pre>
 * <li> dann beide clients starten mit jeweils
<pre>
java de.tubs.cs.iti.krypto.protokoll.CmdLineClient PROTOCOL HOST PORT
</pre>
 * </ol>
 * @author <a href="l.girndt @tu-bs.de">Lars Girndt</a>
 *
 */
public class CmdLineClient implements IClient {

	String host;
	int port;
	String protocolName;

	int playerNumber = 0;

	Communicator com = null;
	/**
	 * 
	 */
	public CmdLineClient(String protocolName, String host, int port) {
		super();
		this.host = host;
		this.port = port;
		this.protocolName = protocolName;
	}

	/* (non-Javadoc)
	 * @see de.tubs.cs.iti.krypto.protokoll.IClient#end(java.lang.String)
	 */
	public void end(String message) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see de.tubs.cs.iti.krypto.protokoll.IClient#playerNumberChanged(int)
	 */
	public void playerNumberChanged(int newPlayerNumber) {
		// TODO Auto-generated method stub
		playerNumber = newPlayerNumber;
		
		// if player number 2 let's start
		if(com!= null){
			if(1 == com.myNumber()){
				com.sendTo(-1,"go");	
			}
		}
	}

	public void connect() {
		try {
			// create protocol
			Protocol protocol =
				(Protocol) Class.forName(protocolName).newInstance();
			// and communicator
			com =
				new Communicator(host, port, "A Server", 2, 2, this);
			protocol.setCommunicator(com);
			// if we are first, we wait, else we start the game
			if (playerNumber < 2) {
				System.out.println("wait for other players "+com.playerNumber());
				com.waitForPlayers();
			} 
			
			System.out.println("start your engines");
			
			// and now: do processing
			if (com.myNumber() > 0){		
				System.out.println("I am receiving first");
				protocol.receiveFirst();
			}
			else {			
				System.out.println("I am sending first");
				protocol.sendFirst();
			}
			System.out.println("finish");
			com.sendTo(-2,String.valueOf(0));
			if(com!=null){
				com.sendTo(-2, String.valueOf(com.myNumber()));
			}
		} catch (Exception e) {
			// TODO: handle exception
			System.err.println("An Exception occured: " + e.getMessage());
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {
		if (args.length!=3) {
			System.out.println("param: ProtocolClass Host Port");
			System.exit(0);			
		}
		try {
			CmdLineClient client = new CmdLineClient(args[0],args[1], 
				Integer.parseInt(args[2]));
			client.connect();
		} catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
