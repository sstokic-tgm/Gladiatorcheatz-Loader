package XxharCs.dbc;

import com.mysql.jdbc.jdbc2.optional.*;
import java.sql.*;

/**
 * This class connects to the database and handles different executions on the database.
 * 
 * @author XxharCs
 * @version 0.1
 */
public class ConnectionLogic
{
	protected Connection con;
	protected MysqlDataSource ds;

	/**
	 * Constructor which creates a connection to the database.
	 * We are setting the transaction isolation level to serializable to avoid incosistency when multiple clients are connected to
	 * the same database.
	 * 
	 * @throws SQLException if the connection fails
	 */
	public ConnectionLogic() throws SQLException
	{
		ds = new MysqlDataSource();

		ds.setServerName("127.0.0.1");
		ds.setPort(3306);
		ds.setUser("username");
		ds.setPassword("password");
		ds.setDatabaseName("databasename");

		con = ds.getConnection();
		con.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
		con.setAutoCommit(false);
	}

	/**
	 * Searches the table fglad_user for the users usergroupid.
	 * 
	 * @param username
	 * @return the ResultSet object
	 * @throws SQLException if the search query fails
	 */
	public ResultSet queryUserGroupId(String username) throws SQLException
	{
		PreparedStatement st = con.prepareStatement("SELECT usergroupid FROM fglad_user WHERE username = ?;", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
		st.setString(1, username);

		ResultSet rs = st.executeQuery();
		con.commit();

		return rs;
	}

	/**
	 * Searches the table fglad_hwid for the specified user.
	 * 
	 * @param username
	 * @return the ResultSet object
	 * @throws SQLException if the search query fails
	 */
	public ResultSet queryUserHwid(String username) throws SQLException
	{
		PreparedStatement st = con.prepareStatement("SELECT * FROM fglad_hwid WHERE username = ?;", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
		st.setString(1, username);

		ResultSet rs = st.executeQuery();
		con.commit();

		return rs;
	}
	
	/**
	 * Searches the table flgad_hwid for the specified hwid.
	 * 
	 * @param hwid
	 * @return the ResultSet object
	 * @throws SQLException if the search query fails
	 */
	public ResultSet queryHwid(String hwid) throws SQLException
	{
		PreparedStatement st = con.prepareStatement("SELECT * FROM fglad_hwid WHERE hwid = ?;", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
		st.setString(1, hwid);

		ResultSet rs = st.executeQuery();
		con.commit();

		return rs;
	}

	/**
	 * Inserts a new user with it's hwid to the hwid table.
	 * 
	 * @param username
	 * @param hwid the user's hwid
	 * @throws SQLException if the insert query fails
	 */
	public void queryAddUserHwid(String username, String hwid) throws SQLException
	{
		PreparedStatement st = con.prepareStatement("INSERT INTO fglad_hwid (username, hwid) VALUES(?, ?);", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
		st.setString(1, username);
		st.setString(2, hwid);

		st.executeUpdate();
		con.commit();
	}
	
	/**
	 * Closes the database connection.
	 * 
	 * @throws SQLException if it failed to close the connection for whatever reason
	 */
	public void disconnect() throws SQLException
	{
		con.close();
		con = null;
	}
}