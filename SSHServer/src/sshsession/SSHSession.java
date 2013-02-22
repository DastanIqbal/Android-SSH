package sshsession;

import crypto.AES128CBC;
import crypto.Compression;
import crypto.HMACSHA1;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import constant.SSHNumbers;

public class SSHSession {
	public String hostName;
	public String userName;
	public byte[] E;
	public  byte[] F;
	public  byte[] H;//session_id
	public  byte[] K;//session secret key
	public  byte[] serverID;//V_S
	public  byte[] clientID;//V_C
	public  byte[] I_C;//payload Client
	public  byte[] I_S;//payload Server
	
	public  int seqIn=0;
	public  int seqOut=0;
	public  byte[] sessionID;
	
	public  static RSAPublicKey serverPublicKey;
	public  static RSAPrivateKey serverPrivateKey;
	public  static byte[] K_S;//server key
	
	public  byte[] IVc2s;
	public  byte[] IVs2c;
	public  byte[] Ec2s;
	public  byte[] Es2c;
	public  byte[] MACc2s;
	public  byte[] MACs2c; 
	public  int cipherBlocksize;
	//must save the current command here
	
	public  AES128CBC cipherC2S;
	public  AES128CBC cipherS2C;
	
	public  HMACSHA1 HASHC2S;
	public  HMACSHA1 HASHS2C;
	
	public boolean useCompression=true;
	public Compression inflater=null;
	public Compression deflater=null;
	
	public static void generateServerKey(){
		//K_S is server public key
				/*4 bytes - unsigned int: length X of string to come
				X bytes - string: this will be 'ssh-rsa' (7 chars)

				4 bytes - unsigned int: length Y of byte array
				Y bytes - bigint of 'e'

				4 bytes - unsigned int: length Z of byte array
				Z bytes - bigint of 'n'*/
				KeyPairGenerator kpg;
				try {
					kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(2048);
					KeyPair kp = kpg.genKeyPair();
					RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
					RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
					serverPrivateKey=privateKey;
					serverPublicKey=publicKey;
					ByteArrayOutputStream byteOut=new ByteArrayOutputStream();
					DataOutputStream ksStream=new DataOutputStream(byteOut);
					ksStream.writeInt(7);
					String type="ssh-rsa";
					ksStream.write(type.getBytes(SSHNumbers.charSet));
					byte[] ee=publicKey.getPublicExponent().toByteArray();
					byte[] n=publicKey.getModulus().toByteArray();
					ksStream.writeInt(ee.length);
					ksStream.write(ee);
					ksStream.writeInt(n.length);
					ksStream.write(n);
					K_S=byteOut.toByteArray();			
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	}
}
