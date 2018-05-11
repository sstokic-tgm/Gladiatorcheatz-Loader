package XxharCs.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.log4j.*;

/**
 * This class is setting up the server connection. It starts the read and send handlers and as also the
 * ServerListener which proceeds the received messages.
 * 
 * @author XxharCs
 * @version 0.1
 */
public class Server
{
	private final static Logger logger = LogManager.getLogger(Server.class);

	protected ServerSocket m_ServerSocket = null;
	protected int m_iPort;

	public Server(int port)
	{
		this.m_iPort = port;

		try
		{
			startConnection();

		} catch (IOException e)
		{
			logger.error("Failed to create the server!", e);
		}
	}

	/**
	 * Here we start the server connection and start the ServerListener
	 */
	private void startConnection() throws IOException
	{
		m_ServerSocket = new ServerSocket(m_iPort);

		logger.info("Server successfully started!");

		try
		{
			while(true)
			{
				Socket socket = m_ServerSocket.accept();

				ClientInfo client = new ClientInfo();
				client.setSocket(socket);

				ClientHandler clientHandler = new ClientHandler(client);
				client.setClientHandler(clientHandler);

				Thread clientHandlerThread = new Thread(clientHandler);
				clientHandlerThread.start();
			}
		}
		finally
		{
			m_ServerSocket.close();
		}
	}
}