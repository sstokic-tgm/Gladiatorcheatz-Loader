package XxharCs.server;

import java.net.Socket;

/**
 * This class has the information of a client.
 * 
 * @author XxharCs
 * @version 0.1
 */
public class ClientInfo {

	private Socket m_sSocket = null;
	private ClientHandler m_ClientHandler = null;

	public void setSocket(Socket socket) {

		m_sSocket = socket;
	}

	public void setClientHandler(ClientHandler clientHandler) {

		m_ClientHandler = clientHandler;
	}

	public Socket getSocket() {

		return m_sSocket;
	}

	public ClientHandler getReadHandler() {

		return m_ClientHandler;
	}
}