package XxharCs.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import XxharCs.enums.PacketType;

public class ClientHandler implements Runnable
{
	private final static Logger logger = LogManager.getLogger(ClientHandler.class);

	protected ClientInfo m_ClientInfo;
	protected DataInputStream m_InputStream;
	protected DataOutputStream m_OutputStream;
	protected PacketHandler packethandler;

	protected volatile boolean m_bRunning = false;

	public ClientHandler(ClientInfo client) throws IOException
	{
		this.m_ClientInfo = client;

		Socket client_socket = m_ClientInfo.getSocket();

		m_InputStream = new DataInputStream(client_socket.getInputStream());
		m_OutputStream = new DataOutputStream(client_socket.getOutputStream());

		packethandler = new PacketHandler();
	}

	@Override
	public void run()
	{	
		boolean bIsAuthenticated = false;
		boolean bIsAuthenticatedFirstRun = false;
		boolean bIsAlive = false;

		try
		{
			while(!m_bRunning)
			{	
				byte[] messageByte = new byte[512];
				int bytesRead = 0;

				messageByte[0] = m_InputStream.readByte(); // 0/len
				messageByte[1] = m_InputStream.readByte(); // 0/len
				messageByte[2] = m_InputStream.readByte(); // 0/len
				messageByte[3] = m_InputStream.readByte(); // 0/len
				messageByte[4] = m_InputStream.readByte(); // 0/len
				messageByte[5] = m_InputStream.readByte(); // packet type

				int packet_length = ByteBuffer.wrap(messageByte).order(ByteOrder.LITTLE_ENDIAN).getInt();
				int packet_type = messageByte[5];

				messageByte = new byte[packet_length];
				bytesRead = m_InputStream.read(messageByte); // body

				PacketType pt = PacketType.fromInt(packet_type);

				switch(pt)
				{
				case AUTH_INIT:

					PacketType result = packethandler.HandleAuthInit(messageByte, bytesRead, bIsAuthenticatedFirstRun, false);
					if(!bIsAuthenticatedFirstRun && result == PacketType.SUCCESS)
					{
						bIsAuthenticatedFirstRun = true;
						bIsAuthenticated = true;
					}
					else
					{
						bIsAuthenticatedFirstRun = false;
						bIsAuthenticated = false;
					}

					if(bIsAuthenticated || result == PacketType.SUCCESS)
						bIsAlive = true;
					else
						bIsAlive = false;
					
					if(result != PacketType.SUCCESS)
					{
						byte[] failure_packet = {0x01, 0x00, (byte)result.getCode()};
						m_OutputStream.write(failure_packet);
						m_OutputStream.flush();
						
						logger.warn(m_ClientInfo.getSocket().getRemoteSocketAddress().toString() + " has modified the hosts file!");
					}
					else
					{
						byte[] success_packet = {0x01, 0x00, (byte)result.getCode()};
						m_OutputStream.write(success_packet);
						m_OutputStream.flush();
					}

					break;
					
				case KEEP_ALIVE:
					
					if((!bIsAlive || !bIsAuthenticated) && !bIsAuthenticatedFirstRun)
					{
						setIsRunning();
						m_ClientInfo.getSocket().close();
						break;
					}
					
					PacketType keepalive_result = packethandler.HandleAuthInit(messageByte, bytesRead, bIsAuthenticatedFirstRun, bIsAuthenticated);
					if(keepalive_result == PacketType.SUCCESS)
					{
						byte[] success_packet = {0x01, 0x00, (byte)keepalive_result.getCode()};
						m_OutputStream.write(success_packet);
						m_OutputStream.flush();
						
						bIsAlive = true;
					}
					else
					{
						byte[] failure_packet = {0x01, 0x00, (byte)keepalive_result.getCode()};
						m_OutputStream.write(failure_packet);
						m_OutputStream.flush();
						
						bIsAlive = false;
						
						logger.warn("The connection to " + m_ClientInfo.getSocket().getRemoteSocketAddress().toString() + " suddenly stopped!");
					}
					
					break;

				case AUTH_LOGIN:

					if((bIsAuthenticatedFirstRun || !bIsAuthenticatedFirstRun) && (!bIsAuthenticated || !bIsAlive))
					{
						setIsRunning();
						m_ClientInfo.getSocket().close();
						break;
					}

					PacketType login_result = packethandler.HandleAuthLogin(messageByte, bytesRead, m_ClientInfo.getSocket().getRemoteSocketAddress());

					if(login_result != PacketType.SUCCESS)
					{
						byte[] failure_packet = {0x01, 0x00, (byte)login_result.getCode()};
						m_OutputStream.write(failure_packet);
						m_OutputStream.flush();
					}
					else
					{
						byte[] success_packet = {0x01, 0x00, (byte)login_result.getCode()};
						m_OutputStream.write(success_packet);
						m_OutputStream.flush();
						
						byte[] file_data = readBytesFromFile("./harCs.set");
						byte[] packet = new byte[file_data.length + 4];
						ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putInt(file_data.length);
						System.arraycopy(file_data, 0, packet, 4, file_data.length);
						m_OutputStream.write(packet);
						m_OutputStream.flush();
						
						setIsRunning();
						m_ClientInfo.getSocket().close();
					}

					break;
				}
			}
		}
		catch(Exception e) {}

		setIsRunning();
	}

	/**
	 * Sets the running variable to false, to cleanly shutdown the thread.
	 */
	public void setIsRunning()
	{

		m_bRunning = true;
	}
	
	/**
	 * Reads a file and converts it to a byte-array
	 * 
	 * @param file the file to be read
	 * @return the file in a byte-array
	 * @throws IOException if the read operation fails
	 */
	public byte[] readBytesFromFile(String file) throws IOException
	{
		RandomAccessFile raf = new RandomAccessFile(file, "rw");
		
		byte[] byteArray = new byte[(int)raf.length()];
		raf.readFully(byteArray);
		
		raf.close();
		
		return byteArray;
	}
}