package keyexchange;
import java.net.*;

import crypto.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import java.io.*;

import com.jcraft.jzlib.JZlib;

import constant.SSHNumbers;

import sshclient.SSHClient;
import sshsession.session;
import sshtransport.Buffer;
import sshtransport.TransportPacket;
public class keyExchange {
	private DataInputStream inStream;
	private DataOutputStream outStream;
	private DiffieHellmanGroup1 crypt;
	public keyExchange(DataInputStream i, DataOutputStream o){
		this.inStream=i;
		this.outStream=o;
	}
	public void recvKeyExchangeInit() throws IOException{
		DataInputStream dataInSt=null;//new DataInputStream(inStream);
		KeyExInit keyInit=new KeyExInit();
		TransportPacket packet=new TransportPacket();
		packet.readPacket(inStream);
		byte[] payLoad=packet.getpayLoad();
		session.I_S=payLoad;
		dataInSt=new DataInputStream(new ByteArrayInputStream(payLoad));
		//keyInit.packetLength=dataInSt.readInt();
		//keyInit.packetLength=dataInSt.readByte();
		keyInit.MsgCode=dataInSt.readByte();
		dataInSt.readFully(keyInit.cookies);
		keyInit.key_al_str=readNameList(dataInSt);
		keyInit.key_al_len=keyInit.key_al_str.length();
		keyInit.host_key_al_str=readNameList(dataInSt);
		keyInit.host_key_al_len=keyInit.host_key_al_str.length();
		keyInit.encr_cl_sr_str=readNameList(dataInSt);
		keyInit.encr_cl_sr_len=keyInit.encr_cl_sr_str.length();
		keyInit.encr_sr_cl_str=readNameList(dataInSt);
		keyInit.encr_sr_cl_len=keyInit.encr_sr_cl_str.length();
		keyInit.mac_cl_sr_str=readNameList(dataInSt);
		keyInit.mac_cl_sr_len=keyInit.mac_cl_sr_str.length();
		keyInit.mac_sr_cl_str=readNameList(dataInSt);
		keyInit.mac_sr_cl_len=keyInit.mac_sr_cl_str.length();
		keyInit.com_cl_sr_str=readNameList(dataInSt);
		keyInit.com_cl_sr_len=keyInit.com_cl_sr_str.length();
		keyInit.com_sr_cl_str=readNameList(dataInSt);
		keyInit.com_sr_cl_len=keyInit.com_sr_cl_str.length();
		keyInit.lang_cl=dataInSt.readInt();
		keyInit.lang_sr=dataInSt.readInt();
		keyInit.KEX_follow=dataInSt.readByte();
		keyInit.reserved=dataInSt.readInt();
		//byte[] temp=new byte[keyInit.paddingLength];
		//dataInSt.readFully(temp);
		//keyInit.paddle=new String(temp,SSHNumbers.charSet);
		
	}
	public void doKeyExchange() throws Exception{
		recvKeyExchangeInit();
		sendKeyExchangeInit();
		sendDHExchangeInit();
		recvServerNewKey();
		calKey();
		sendAuthenServiceRequest();
		recvAuthenServiceReply();
	}
	private void calKey() throws Exception{
		try{
			SHA1 hash=new SHA1();
			hash.init();
			//Code from JSch library
			if (session.sessionID==null){
				session.sessionID=new byte[session.H.length];
				System.arraycopy(session.H,0, session.sessionID, 0,session.H.length);
			}
			Buffer buf=new Buffer();
			buf.putMPInt(session.K);
			buf.putByte(session.H);
			buf.putByte((byte)0x41);//letter A
			buf.putByte(session.sessionID);
			hash.update(buf.buffer,0,buf.index);
			
			session.IVc2s=hash.digest();
			
			//change "A" -> "B"
			int j=buf.index-session.sessionID.length-1;
			buf.buffer[j]++;
			hash.update(buf.buffer,0,buf.index);
			
			session.IVs2c=hash.digest();
			
			buf.buffer[j]++;
			hash.update(buf.buffer,0,buf.index);
			
			session.Ec2s=hash.digest();
			
			buf.buffer[j]++;
			hash.update(buf.buffer,0,buf.index);
			
			session.Es2c=hash.digest();
			
			buf.buffer[j]++;
			hash.update(buf.buffer,0,buf.index);
			
			session.MACc2s=hash.digest();
			
			buf.buffer[j]++;
			hash.update(buf.buffer,0,buf.index);
			
			session.MACs2c=hash.digest();
			
			//Init the encrypt and hashing algorithm from S to C
			session.cipherS2C=new AES128CBC();
			while(session.cipherS2C.getBlockSize()>session.Es2c.length){
		        buf.reset();
		        buf.putMPInt(session.K);
		        buf.putByte(session.H);
		        buf.putByte(session.Es2c);
		        hash.update(buf.buffer, 0, buf.index);
		        byte[] foo=hash.digest();
		        byte[] bar=new byte[session.Es2c.length+foo.length];
			System.arraycopy(session.Es2c, 0, bar, 0, session.Es2c.length);
			System.arraycopy(foo, 0, bar, session.Es2c.length, foo.length);
			session.Es2c=bar;
		    }
		    session.cipherS2C.init(AES128CBC.DECRYPT_MODE, session.Es2c, session.IVs2c);
		    //update cypherBlocksize
		    session.cipherBlocksize=session.cipherS2C.getIVSize();
		    
		    //Init HMAC S2C function
		    session.HASHS2C=new HMACSHA1();
		    session.HASHS2C.init(session.MACs2c);
		    
		  //Init the encrypt and hashing algorithm from C to S
			session.cipherC2S=new AES128CBC();
			while(session.cipherC2S.getBlockSize()>session.Ec2s.length){
		        buf.reset();
		        buf.putMPInt(session.K);
		        buf.putByte(session.H);
		        buf.putByte(session.Ec2s);
		        hash.update(buf.buffer, 0, buf.index);
		        byte[] foo=hash.digest();
		        byte[] bar=new byte[session.Ec2s.length+foo.length];
			System.arraycopy(session.Ec2s, 0, bar, 0, session.Ec2s.length);
			System.arraycopy(foo, 0, bar, session.Ec2s.length, foo.length);
			session.Ec2s=bar;
		    }
		    session.cipherC2S.init(AES128CBC.ENCRYPT_MODE, session.Ec2s, session.IVc2s);
		    //update cypherBlocksize
		    session.cipherBlocksize=session.cipherC2S.getIVSize();
		    
		    //Init HMAC S2C function
		    session.HASHC2S=new HMACSHA1();
		    session.HASHC2S.init(session.MACc2s);
		    
		    //Init compressor!!!
		    if (session.useCompression){
		    	initInflater();
		    	initDeflater();
		    }
		}
		catch (Exception e){
			throw e;
		}
	}
	private void initInflater(){
		session.inflater=new Compression();
		session.inflater.init(Compression.INFLATER, JZlib.Z_DEFAULT_COMPRESSION);
	}
	private void initDeflater(){
		session.deflater=new Compression();
		session.deflater.init(Compression.DEFLATER,JZlib.Z_DEFAULT_COMPRESSION);
	}
	
	private String readNameList(DataInputStream stream) throws IOException{
		int length=stream.readInt();
		byte[] temp=new byte[length];
		stream.readFully(temp);
		String data=new String(temp,SSHNumbers.charSet);
		return data;		
	}
	private void writeNameList(DataOutputStream stream,String data) throws IOException{
		stream.writeInt(data.length());
		stream.write(data.getBytes(SSHNumbers.charSet));
	}
	public void sendKeyExchangeInit() throws Exception{
		//DataOutputStream dataOutSt=new DataOutputStream(outStream);
		DataOutputStream dataOutSt;//=outStream;
		ByteArrayOutputStream byteStream=new ByteArrayOutputStream();
		dataOutSt=new DataOutputStream(byteStream);
		KeyExInit keyInit=new KeyExInit();
		try{
			keyInit.MsgCode=SSHNumbers.SSH_MSG_KEXINIT;
			byte[] cookies=new byte[16];
			Random rand=new SecureRandom();
			rand.nextBytes(cookies);
			keyInit.cookies=cookies;
			//SSHClient.current_cookies=cookies;
			keyInit.key_al_str="diffie-hellman-group1-sha1";
			//keyInit.key_al_str="diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
			keyInit.key_al_len=keyInit.key_al_str.length();
			keyInit.host_key_al_str="ssh-rsa";
			//keyInit.host_key_al_str="ssh-rsa,ssh-dss";
			keyInit.host_key_al_len=keyInit.host_key_al_str.length();
			keyInit.encr_cl_sr_str="aes128-cbc";
			//keyInit.encr_cl_sr_str="aes256-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,rijndael192-cbc,aes128-cbc,rijndael128-cbc,blowfish-cbc,3des-cbc";
			keyInit.encr_cl_sr_len=keyInit.encr_cl_sr_str.length();
			keyInit.encr_sr_cl_str="aes128-cbc";
			//keyInit.encr_sr_cl_str="aes256-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,rijndael192-cbc,aes128-cbc,rijndael128-cbc,blowfish-cbc,3des-cbc";
			keyInit.encr_sr_cl_len=keyInit.encr_sr_cl_str.length();
			keyInit.mac_cl_sr_str="hmac-sha1";
			//keyInit.mac_cl_sr_str="hmac-sha1,hmac-md5,none";
			keyInit.mac_cl_sr_len=keyInit.mac_cl_sr_str.length();
			keyInit.mac_sr_cl_str="hmac-sha1";
			//keyInit.mac_sr_cl_str="hmac-sha1,hmac-md5,none";
			keyInit.mac_sr_cl_len=keyInit.mac_sr_cl_str.length();
			if (session.useCompression==false)
				keyInit.com_cl_sr_str="none,zlib";
			else
				keyInit.com_cl_sr_str="zlib,none";
			keyInit.com_cl_sr_len=keyInit.com_cl_sr_str.length();
			keyInit.com_sr_cl_str="none,zlib";
			keyInit.com_sr_cl_len=keyInit.com_sr_cl_str.length();
			keyInit.lang_cl=0;
			keyInit.lang_sr=0;
			keyInit.KEX_follow=0;
			keyInit.reserved=0;
			
			dataOutSt.writeByte(keyInit.MsgCode);
			dataOutSt.write(cookies);
			//dataOutSt.flush();
			writeNameList(dataOutSt, keyInit.key_al_str);
			writeNameList(dataOutSt, keyInit.host_key_al_str);
			writeNameList(dataOutSt, keyInit.encr_cl_sr_str);
			writeNameList(dataOutSt, keyInit.encr_sr_cl_str);
			writeNameList(dataOutSt, keyInit.mac_cl_sr_str);
			writeNameList(dataOutSt, keyInit.mac_sr_cl_str);
			writeNameList(dataOutSt, keyInit.com_cl_sr_str);
			writeNameList(dataOutSt, keyInit.com_sr_cl_str);
			dataOutSt.writeInt(keyInit.lang_cl);
			dataOutSt.writeInt(keyInit.lang_sr);
			dataOutSt.writeInt(keyInit.KEX_follow);
			dataOutSt.writeByte(keyInit.reserved);
			
			dataOutSt.flush();
			
			TransportPacket packet=new TransportPacket();
			session.I_C=byteStream.toByteArray();
			packet.setpayLoad(session.I_C);
			packet.send(outStream);
			//dataOutSt.close();
		}
		catch (IOException e){
			//e.printStackTrace();
			//System.out.println(e.getMessage());
			throw e;
		}
	}
	public void sendDHExchangeInit() throws Exception{
		try{
			byte MsgCode=SSHNumbers.SSH_MSG_KEXDH_INIT;
			crypt=new DiffieHellmanGroup1();
			byte[] e=crypt.getE();
			session.E=e;
			Buffer buffer=new Buffer();
			buffer.putByte(MsgCode);
			buffer.putMPInt(e);
			//byteStream.write(MsgCode);
			//byteStream.write(e);
			TransportPacket transport=new TransportPacket();
			byte[] data=new byte[buffer.getLength()];
			buffer.getByte(data);
			transport.setpayLoad(data);
			//transport.calLength();
			transport.send(this.outStream);
		}
		catch (Exception e){
			//e.printStackTrace();
			throw e;
		}
	}
	public void recvServerNewKey() throws Exception{
		TransportPacket packet=new TransportPacket();
		try {
			packet.readPacket(inStream);
		} catch (SocketException se) {
			// TODO Auto-generated catch block
			throw se;
		}
		Buffer buffer=new Buffer(packet.getpayLoad());
		int msgCode=buffer.getByte();
		session.K_S=buffer.getString();
		session.F=buffer.getMPInt();
		crypt.setF(session.F);
		//session.H=buffer.getString();
		byte[] sig_H=buffer.getString();
		try{
			session.K=crypt.getK();
		}
		catch (Exception e){
			throw e;
		}
		//verify H
		buffer=new Buffer();
		buffer.putString(session.clientID);
		buffer.putString(session.serverID);
		buffer.putString(session.I_C);
		buffer.putString(session.I_S);
		buffer.putString(session.K_S);
		buffer.putMPInt(session.E);
		buffer.putMPInt(session.F);
		buffer.putMPInt(session.K);
		MessageDigest md=null;
		try{
			md=MessageDigest.getInstance("SHA-1");
		}
		catch (Exception e){
			throw e;
		}
		byte[] temp=new byte[buffer.getLength()];
		buffer.getByte(temp);
		md.update(temp);
		session.H=md.digest();
		SignatureRSA sig=new SignatureRSA();
		try {
			sig.init();
			byte[] tmp;
			byte[] ee;
			byte[] n; 
			//Code from jsch library
			int i=0,j=0;
		    j=((session.K_S[i++]<<24)&0xff000000)|((session.K_S[i++]<<16)&0x00ff0000)|
			((session.K_S[i++]<<8)&0x0000ff00)|((session.K_S[i++])&0x000000ff);
		    i+=j;
		    j=((session.K_S[i++]<<24)&0xff000000)|((session.K_S[i++]<<16)&0x00ff0000)|
		    		((session.K_S[i++]<<8)&0x0000ff00)|((session.K_S[i++])&0x000000ff);
		    tmp=new byte[j]; System.arraycopy(session.K_S, i, tmp, 0, j); i+=j;
		    ee=tmp;
		    j=((session.K_S[i++]<<24)&0xff000000)|((session.K_S[i++]<<16)&0x00ff0000)|
		    ((session.K_S[i++]<<8)&0x0000ff00)|((session.K_S[i++])&0x000000ff);
		    tmp=new byte[j]; System.arraycopy(session.K_S, i, tmp, 0, j); i+=j;
		    n=tmp;
		    
		    sig.setPubKey(ee, n);   
			sig.update(session.H);
			boolean result=sig.verify(sig_H); 
			if (result){
				//System.out.println(result);
				packet=new TransportPacket();
				packet.readPacket(inStream);//read new key
				boolean check=packet.getpayLoad()[0]==21? true:false;
				packet=new TransportPacket();
				buffer=new Buffer();
				buffer.putByte((byte)21);
				packet.payLoad=new byte[1];
				buffer.getByte(packet.payLoad);
				packet.send(outStream);
			}
			else{
				System.out.println("Error hashing code, quit!");
				//System.exit(-1);
				throw new Exception("Error hashing code");
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw e;
		}
		
	}
	private void sendAuthenServiceRequest() throws Exception{
		try{
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_SERVICE_REQUEST);
			buffer.putString(SSHNumbers.AuthenserviceName.getBytes(SSHNumbers.charSet));
			TransportPacket packet=new TransportPacket();
			packet.setpayLoad(buffer);
			packet.send(outStream);
		}
		catch (Exception e){
			throw e;
		}
	}
	private void recvAuthenServiceReply() throws Exception{
		try{
			TransportPacket packet=new TransportPacket();
			packet.readPacket(inStream);
			Buffer buffer=new  Buffer(packet.getpayLoad());
			int msg=buffer.getByte();
			byte[] service=buffer.getString();
			String serviceStr=new String(service,SSHNumbers.charSet);
			//System.out.println(serviceStr);
		}
		catch (Exception e){
			throw e;
		}
	}
class KeyExInit{
		//int packetLength;
		//byte paddingLength;
		byte MsgCode;
		byte[] cookies=new byte[16];
		int key_al_len;
		String key_al_str;
		int host_key_al_len;
		String host_key_al_str;
		int encr_cl_sr_len;
		String encr_cl_sr_str;
		int encr_sr_cl_len;
		String encr_sr_cl_str;
		int mac_cl_sr_len;
		String mac_cl_sr_str;
		int mac_sr_cl_len;
		String mac_sr_cl_str;
		int com_cl_sr_len;
		String com_cl_sr_str;
		int com_sr_cl_len;
		String com_sr_cl_str;
		int lang_cl;
		int lang_sr;
		byte KEX_follow;
		int reserved;
		//String paddle;
	}
	
}
