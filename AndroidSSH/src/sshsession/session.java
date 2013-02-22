package sshsession;

import crypto.AES128CBC;
import crypto.Compression;
import crypto.HMACSHA1;

public class session {
	public static String hostName;
	public static byte[] E;
	public static byte[] F;
	public static byte[] H;//session_id
	public static byte[] K;//session secret key
	public static byte[] serverID;//V_S
	public static byte[] clientID;//V_C
	public static byte[] I_C;//payload Client
	public static byte[] I_S;//payload Server
	public static byte[] K_S;//server key
	public static int seqIn;
	public static int seqOut;
	public static byte[] sessionID;
	
	public static boolean useCompression=true;
	
	public static byte[] IVc2s;
	public static byte[] IVs2c;
	public static byte[] Ec2s;
	public static byte[] Es2c;
	public static byte[] MACc2s;
	public static byte[] MACs2c; 
	public static int cipherBlocksize;
	//must save the current command here
	public static String currentCommand;
	public static String userName;
	public static String password;
	
	public static AES128CBC cipherC2S;
	public static AES128CBC cipherS2C;
	
	public static HMACSHA1 HASHC2S;
	public static HMACSHA1 HASHS2C;
	
	public static Compression inflater=null;
	public static Compression deflater=null;
	
	public static void clear(){
		//E=null;
		//F=null;
		//H=null;
		//K=null;
		cipherBlocksize=0;
		cipherC2S=null;
		cipherS2C=null;
		HASHC2S=null;
		HASHS2C=null;
		inflater=null;
		deflater=null;
		sessionID=null;
		seqIn=seqOut=0;
	}
}
