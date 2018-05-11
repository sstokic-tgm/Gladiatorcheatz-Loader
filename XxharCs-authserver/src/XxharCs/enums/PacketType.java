package XxharCs.enums;

public enum PacketType
{
	AUTH_INIT(0x01), // by client
	AUTH_LOGIN(0x02), // by client
	AUTH_INVALID(0x03), // by server
	KEEP_ALIVE(0x04), // by client
	INVALID_USERNAME_PASSWORD(0x05), // by server
	NOT_FOUND(0x06), // by server
	NO_VIP(0x07), // by server
	INVALID_HWID(0x08), // by server
	SUCCESS(0x09); // by server
	
	private int code;
	
	PacketType(int code)
	{
		this.code = code;
	}

	public int getCode()
	{
		return code;
	}
	
	public static PacketType fromInt(int i)
	{
		for(PacketType pt : PacketType.values())
		{
			if(pt.getCode() == i)
				return pt;
		}
		return null;
	}
}