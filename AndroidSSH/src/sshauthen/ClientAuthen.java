package sshauthen;
import sshtransport.*;
import constant.*;
import java.io.*;
import sshclient.*;
public class ClientAuthen {
	public String userName;
	public String passWord;
	private InputStream iStream;
	private OutputStream oStream;
	public ClientAuthen(String uName,String pass,InputStream iStream,OutputStream oStream){
		this.userName=uName;
		this.passWord=pass;
		this.iStream=iStream;
		this.oStream=oStream;
	}
	public boolean doAuthen() throws Exception{
		sendAuthenRequest();
		return getAuthenResult();
		
	}
	public void sendAuthenRequest() throws Exception{
		try{
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_USERAUTH_REQUEST);
			buffer.putString(userName.getBytes(SSHNumbers.charSet));
			buffer.putString(SSHNumbers.ConnserviceName.getBytes(SSHNumbers.charSet));
			buffer.putString(SSHNumbers.method.getBytes(SSHNumbers.charSet));
			buffer.putByte((byte)0);
			buffer.putString(passWord.getBytes(SSHNumbers.charSet));
			TransportPacket packet=new TransportPacket();
			packet.setpayLoad(buffer);
			packet.send(oStream);
		}
		catch (Exception e){
			throw e;
		}
	}
	public boolean getAuthenResult() throws Exception{
		TransportPacket packet=new TransportPacket();
		packet.readPacket(iStream);
		Buffer buffer=new Buffer(packet.getpayLoad());
		int result=(byte) buffer.getByte();
		if (result==SSHNumbers.SSH_MSG_USERAUTH_FAILURE){
			return false;
		}
		if (result==SSHNumbers.SSH_MSG_USERAUTH_SUCCESS){
			return true;
		}
		return false;
	}
}
