package XxharCs.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.SocketAddress;
import java.net.URL;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.HttpsURLConnection;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import XxharCs.dbc.ConnectionLogic;
import XxharCs.enums.PacketType;

public class PacketHandler
{
	private final static Logger logger = LogManager.getLogger(PacketHandler.class);

	protected List<String> blacklisted_words = new ArrayList<String>();

	public PacketHandler()
	{
		blacklisted_words.add("gladiator");
		blacklisted_words.add("gladiatorz");
		blacklisted_words.add("gladiatorcheatz");
		blacklisted_words.add("gladiatorcheatz.com");
		blacklisted_words.add("www.gladiatorcheatz.com");
		blacklisted_words.add("176.9.71.43");
	}

	public PacketType HandleAuthInit(byte[] data, int bytesRead, boolean bIsAuthenticatedFirstRun, boolean bIsAuthenticated)
	{	
		if(!bIsAuthenticatedFirstRun)
		{
			String content = new String(data, 0, bytesRead);

			if(!content.contains("C:\\Windows\\System32\\drivers\\etc\\hosts"))
				return PacketType.AUTH_INVALID;
			
			for(String word : blacklisted_words)
			{
				if(content.contains(word))
				{
					return PacketType.AUTH_INVALID;
				}
			}
			
			return PacketType.SUCCESS;
		}
		else
		{
			ConnectionLogic conn_logic = null;

			try
			{
				conn_logic = new ConnectionLogic();
			}
			catch (SQLException e)
			{
				logger.error("An error occured while connecting to the database: ", e);
				return PacketType.AUTH_INVALID;
			}
			
			String body = new String(data, 0, bytesRead);
			String[] body_parts = body.split(";");
			String hwid = body_parts[0];
			
			try
			{
				ResultSet rsHwid = conn_logic.queryHwid(hwid);
				
				int rowCountHwid = rsHwid.last() ? rsHwid.getRow() : 0;
				rsHwid.beforeFirst();
				
				conn_logic.disconnect();
				
				if(rowCountHwid == 0 && !bIsAuthenticated)
					return PacketType.AUTH_INVALID;
				else
					return PacketType.SUCCESS;
			}
			catch (SQLException e)
			{
				logger.error("An error has occured: ", e);
				
				return PacketType.NOT_FOUND;
			}
		}

		//return PacketType.AUTH_INVALID;
	}

	public PacketType HandleAuthLogin(byte[] data, int bytesRead, SocketAddress ip)
	{
		String body = new String(data, 0, bytesRead);
		String[] body_parts = body.split(";");

		String username = body_parts[0];
		String password = body_parts[1];
		String hwid = body_parts[2];

		PacketType result = PacketType.AUTH_INVALID;

		try
		{
			result = PerformLoginCheck(username, password, hwid);
		}
		catch (Exception e)
		{
			result = PacketType.AUTH_INVALID;
		}
		
		if(result == PacketType.SUCCESS)
			logger.info(username + " with the hwid " + hwid + " @" + ip.toString() + " successfully logged in!");

		return result;
	}

	private PacketType PerformLoginCheck(String username, String password, String hwid) throws Exception
	{
		PacketType result;

		String httpsURL = "https://url_to_the_login_site/";
		String query = "username="+username+"&password="+password;

		URL myurl = new URL(httpsURL);
		HttpsURLConnection con = (HttpsURLConnection)myurl.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-length", String.valueOf(query.length()));
		con.setDoOutput(true); 
		con.setDoInput(true); 
		DataOutputStream output = new DataOutputStream(con.getOutputStream());  
		output.writeBytes(query);
		output.close();
		DataInputStream input = new DataInputStream( con.getInputStream() ); 
		String postres = "";
		for(int c = input.read(); c != -1; c = input.read()) 
			postres += (char)c;
		input.close(); 

		if(postres.contains("Logging in..."))
			result = PacketType.SUCCESS;
		else
			result = PacketType.INVALID_USERNAME_PASSWORD;

		if(result == PacketType.SUCCESS)
			result = PerformHWIDCheck(username, hwid);

		return result;
	}

	private PacketType PerformHWIDCheck(String username, String hwid)
	{
		PacketType result = PacketType.NOT_FOUND;
		ConnectionLogic conn_logic = null;
		boolean canContinue = false;

		try
		{
			conn_logic = new ConnectionLogic();
		}
		catch (SQLException e)
		{
			logger.error("An error occured while connecting to the database: ", e);
			return PacketType.NOT_FOUND;
		}

		try
		{
			ResultSet rsGroupId = conn_logic.queryUserGroupId(username);

			int rowCountGroupId = rsGroupId.last() ? rsGroupId.getRow() : 0;
			rsGroupId.beforeFirst();

			if(rowCountGroupId == 0)
			{
				result = PacketType.NOT_FOUND;
				return result;
			}
			else if(rowCountGroupId == 1)
			{
				rsGroupId.next();
				
				int groupId = rsGroupId.getInt("usergroupid");

				if(groupId == 14 || groupId == 6)
				{
					canContinue = true;
					result = PacketType.SUCCESS;
				}
				else
				{
					canContinue = false;
					result = PacketType.NO_VIP;
				}
			}

			if(result == PacketType.SUCCESS && canContinue)
			{
				ResultSet rsUserHwid = conn_logic.queryUserHwid(username);

				int rowCountUserHwid = rsUserHwid.last() ? rsUserHwid.getRow() : 0;
				rsUserHwid.beforeFirst();

				if(rowCountUserHwid == 0)
				{
					conn_logic.queryAddUserHwid(username, hwid);

					logger.info(username + " got bound on the hwid: " + hwid);
					result = PacketType.SUCCESS;
				}
				else if(rowCountUserHwid == 1)
				{
					rsUserHwid.next();
					
					String result_username = rsUserHwid.getString("username");
					String result_hwid = rsUserHwid.getString("hwid");

					if(Objects.equals(username, result_username) && Objects.equals(hwid, result_hwid))
					{
						result = PacketType.SUCCESS;
					}
					else
						result = PacketType.INVALID_HWID;
				}
			}
		}
		catch (SQLException e)
		{
			result = PacketType.NOT_FOUND;

			logger.error("An error has occured: ", e);
		}

		try
		{
			conn_logic.disconnect();
		}
		catch (SQLException e)
		{
			logger.error("An error occured while disconnecting from the database: ", e);
		}

		return result;
	}
}