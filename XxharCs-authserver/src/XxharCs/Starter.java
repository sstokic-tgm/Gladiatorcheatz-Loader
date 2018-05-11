package XxharCs;

import XxharCs.cli.CLIParser;
import XxharCs.server.Server;

/**
 * Parses command line arguments and starts therefore the server.
 * 
 * @author XxharCs
 * @version 0.1
 */
public class Starter
{
	public static void main(String[] args)
	{
		boolean bSuccessfullyParsed = false;

		CLIParser cli = new CLIParser(args); // pass the command line arguments to the CLIParser
		cli.parse(); // parse the arguments
		bSuccessfullyParsed = cli.getIsEnoughArgs(); // check if we have all arguments

		if(bSuccessfullyParsed)
		{
			new Server(cli.getPort());
		}
	}
}