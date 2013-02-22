package keyexchange;

import crypto.*;

import java.security.*;

import java.util.Random;


import java.io.*;

import constant.SSHNumbers;

//import sshclient.SSHClient;

import sshsession.SSHSession;
import sshtransport.Buffer;
import sshtransport.TransportPacket;
public class keyExchange {
	private DataInputStream inStream;
	private DataOutputStream outStream;
	private SSHSession session;
	private DiffieHellmanGroup1 crypt;
	public keyExchange(InputStream i, OutputStream o, SSHSession session){
		this.inStream=new DataInputStream(i);
		this.outStream=new DataOutputStream(o);
		this.session=session;
	}
	public void recvKeyExchangeInit(){
		DataInputStream dataInSt=null;//new DataInputStream(inStream);
		KeyExInit keyInit=new KeyExInit();
		try{
			TransportPacket packet=new TransportPacket(session);
			packet.readPacket(inStream);
			byte[] payLoad=packet.getpayLoad();
			session.I_C=payLoad;
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
			if (keyInit.com_cl_sr_str.contains("zlib,none")){
				session.useCompression=true;
			}
			else{
				session.useCompression=false;
			}
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
		catch (IOException e){
			e.printStackTrace();
		}
	}
	public void doKeyExchange(){
		sendKeyExchangeInit();
		recvKeyExchangeInit();
		//sendDHExchangeInit();
		//recvServerNewKey();
		//recv Key Exchange Init from client
		RecvKeyEx();
		SendDHKeyReply();
		send_rcv_NewKey();
		calKey();
		recvServiceRequest();
		//sendAuthenServiceRequest();
		//recvAuthenServiceReply();
	}
	/*private void generateK_S(){
		//K_S is server public key
		
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
			session.serverPrivateKey=privateKey;
			session.serverPublicKey=publicKey;
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
			session.K_S=byteOut.toByteArray();			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}*/
	private void RecvKeyEx(){
		TransportPacket packet=new TransportPacket(session);
		packet.readPacket(inStream);
		Buffer buffer=new Buffer(packet.getpayLoad());
		int Msg_Code=buffer.getByte();
		session.E=buffer.getMPInt();		
	}
	private void SendDHKeyReply(){
		Buffer buffer=new Buffer();
		int MsgCode=SSHNumbers.SSH_MSG_KEXDH_REPLY;
		buffer.putByte((byte)MsgCode);
		//generate K_S
		
		try{
			buffer.putString(session.K_S);
			crypt=new DiffieHellmanGroup1();
			crypt.init();
			session.F=crypt.getE();
			//generate key K
			crypt.setF(session.E);
			session.K=crypt.getK();
			buffer.putMPInt(session.F);
			//generate H
			byte[] sign_H=sign_H();
			buffer.putString(sign_H);
			TransportPacket packet=new TransportPacket(session);
			packet.setpayLoad(buffer);
			packet.send(outStream);			
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void send_rcv_NewKey(){
		Buffer buffer=new Buffer();
		buffer.putByte(SSHNumbers.SSH_MSG_NEWKEYS);
		TransportPacket packet=new TransportPacket(session);
		packet.setpayLoad(buffer);
		packet.send(outStream);
		packet=new TransportPacket(session);
		packet.readPacket(inStream);
		byte[] MsgCode=packet.getpayLoad();		
	}
	private byte[] sign_H(){
		Buffer buffer=new Buffer();
		buffer.putString(session.clientID);
		buffer.putString(session.serverID);
		buffer.putString(session.I_C);
		buffer.putString(session.I_S);
		buffer.putString(SSHSession.K_S);
		buffer.putMPInt(session.E);
		buffer.putMPInt(session.F);
		buffer.putMPInt(session.K);
		MessageDigest md=null;
		try{
			md=MessageDigest.getInstance("SHA-1");
		}
		catch (Exception e){
			e.printStackTrace();
		}
		byte[] temp=new byte[buffer.getLength()];
		buffer.getByte(temp);
		md.update(temp);
		session.H=md.digest();
		SignatureRSA sig=new SignatureRSA();		
		try {
			sig.init();
			sig.setPrvKey(SSHSession.serverPrivateKey.getPrivateExponent().toByteArray(),SSHSession.serverPrivateKey.getModulus().toByteArray());
			sig.update(session.H);
			return sig.sign();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}		
	}
	private void calKey(){
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
		    session.cipherS2C.init(AES128CBC.ENCRYPT_MODE, session.Es2c, session.IVs2c);
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
		    session.cipherC2S.init(AES128CBC.DECRYPT_MODE, session.Ec2s, session.IVc2s);
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
			e.printStackTrace();
		}
	}
	private void initInflater(){
		session.inflater=new Compression();
		session.inflater.init(Compression.INFLATER, 0);
	}
	private void initDeflater(){
		session.deflater=new Compression();
		session.deflater.init(Compression.DEFLATER,0);
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
	public void sendKeyExchangeInit(){
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
			keyInit.com_cl_sr_str="none,zlib";
			keyInit.com_cl_sr_len=keyInit.com_cl_sr_str.length();
			keyInit.com_sr_cl_str="none,zlib";
			keyInit.com_sr_cl_len=keyInit.com_sr_cl_str.length();
			keyInit.lang_cl=0;
			keyInit.lang_sr=0;
			keyInit.KEX_follow=0;
			keyInit.reserved=0;
			//int payLoad=keyInit.key_al_len+keyInit.host_key_al_len+keyInit.encr_cl_sr_len+
			//		keyInit.encr_sr_cl_len+keyInit.mac_cl_sr_len+keyInit.mac_sr_cl_len+keyInit.com_cl_sr_len+
			//		keyInit.com_sr_cl_len+18+45;
			//calculate paddingLength
			//int cal=payLoad+4;
			//keyInit.paddingLength=(byte)(8-(cal%8));
			//if (keyInit.paddingLength<4){
			//	keyInit.paddingLength+=8;
			//}
			//keyInit.packetLength=payLoad+keyInit.paddingLength;
			//keyInit.packetLength=500;
			//keyInit.paddingLength=9;
			//sending
			//dataOutSt.writeInt(keyInit.packetLength);
			//dataOutSt.writeByte(keyInit.paddingLength);
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
			//Random ran=new Random();
			//byte[] test=new byte[keyInit.paddingLength];
			//ran.nextBytes(test);
			//keyInit.paddle=new String(test);
			//dataOutSt.write(keyInit.paddle.getBytes(SSHNumbers.charSet));
			dataOutSt.flush();
			//outStream.write(byteStream.toByteArray());
			//int plLength=keyInit.packetLength-keyInit.paddingLength-1;
			//byte[] pLoad=new byte[plLength];
			//System.arraycopy(byteStream.toByteArray(), 5, pLoad, 0, plLength);
			//session.seqOut++;
			TransportPacket packet=new TransportPacket(session);
			session.I_S=byteStream.toByteArray();
			packet.setpayLoad(session.I_S);
			packet.send(outStream);
			//dataOutSt.close();
		}
		catch (IOException e){
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
	}
	
	private void recvServiceRequest(){
		try{
			TransportPacket packet=new TransportPacket(session);
			packet.readPacket(inStream);
			Buffer buffer=new Buffer(packet.getpayLoad());
			int msg=buffer.getByte();
			String serviceName=new String(buffer.getString(),SSHNumbers.charSet);
			if (msg==SSHNumbers.SSH_MSG_SERVICE_REQUEST &&
					serviceName.equals("ssh-userauth")){
				sendServiceAccept();
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void sendServiceAccept(){
		try{
			TransportPacket packet=new TransportPacket(session);
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_SERVICE_ACCEPT);
			buffer.putString(SSHNumbers.AuthenserviceName.getBytes(SSHNumbers.charSet));
			packet.setpayLoad(buffer);
			packet.send(outStream);
		}
		catch (Exception e){
			e.printStackTrace();
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
