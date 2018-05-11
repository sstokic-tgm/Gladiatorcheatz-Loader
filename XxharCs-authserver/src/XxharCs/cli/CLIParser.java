package XxharCs.cli;

import org.apache.commons.cli.*;

/**
 * Command line arguments are parsed in GNU style.
 * 
 * @author XxharCs
 * @version 0.1
 */
public class CLIParser
{
	private String[] m_szArgs;
	private Options m_Options;

	private int m_iPort = 0;

	private boolean m_bEnoughArgs = true;

	public CLIParser(String[] args)
	{
		this.m_szArgs = args;
		this.m_Options = new Options();

		Option port = Option.builder("p")
				.hasArg()
				.desc("Port of the hostname")
				.required(true)
				.build();

		this.m_Options.addOption(port);
	}

	/**
	 * Method that parses the arguments.
	 */
	public void parse()
	{
		DefaultParser parser = new DefaultParser();

		try
		{
			CommandLine line = parser.parse(this.m_Options, this.m_szArgs);

			if(line.hasOption("p"))
			{
				try
				{
					this.m_iPort = Integer.parseInt(line.getOptionValue("p"));
				}
				catch(NumberFormatException nfe)
				{
					this.m_bEnoughArgs = false;
					this.help();
				}
			}
		}
		catch(ParseException pe)
		{
			this.m_bEnoughArgs = false;
			this.help();
		}
	}

	/**
	 * Method that shows an assistance.
	 */
	public void help()
	{
		HelpFormatter hf = new HelpFormatter();
		hf.printHelp("authserver", this.m_Options);
	}

	public boolean getIsEnoughArgs()
	{
		return m_bEnoughArgs;
	}

	public int getPort()
	{
		return m_iPort;
	}
}