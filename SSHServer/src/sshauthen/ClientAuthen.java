package sshauthen;
import sshsession.SSHSession;
import sshtransport.*;
import constant.*;
import java.io.*;

import javax.transaction.TransactionRequiredException;
//import sshserver.*;
public class ClientAuthen {
	public String userName;
	public String passWord;
	private InputStream iStream;
	private OutputStream oStream;
	private SSHSession session;
	public ClientAuthen(InputStream iStream,OutputStream oStream,SSHSession session){
		this.iStream=iStream;
		this.oStream=oStream;
		this.session=session;
	}
	public boolean doAuthen(){
		//sendAuthenRequest();
		//return getAuthenResult();
		recvClientAuthenRequest();		
		return true;
	}
	private void recvClientAuthenRequest(){
		try{
			
			TransportPacket packet=new TransportPacket(session);
			packet.readPacket(iStream);
			Buffer buffer=new Buffer(packet.getpayLoad());
			int MsgCode=buffer.getByte();
			assert(MsgCode==SSHNumbers.SSH_MSG_USERAUTH_REQUEST);
			String userName=new String(buffer.getString(),SSHNumbers.charSet);			
			String serviceName=new String(buffer.getString(),SSHNumbers.charSet);
			assert(serviceName.equals(SSHNumbers.ConnserviceName));
			String method=new String(buffer.getString(),SSHNumbers.charSet);
			assert(method.equals("password"));
			buffer.getByte();
			//buffer.putString(passWord.getBytes(SSHNumbers.charSet));
			String password=new String(buffer.getString(),SSHNumbers.charSet);
			//check username and password
			if (true){
				session.userName=userName;
				sendAuthenSuccResult();
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void sendAuthenRequest(){
		try{
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_USERAUTH_REQUEST);
			buffer.putString(userName.getBytes(SSHNumbers.charSet));
			buffer.putString(SSHNumbers.ConnserviceName.getBytes(SSHNumbers.charSet));
			buffer.putString(SSHNumbers.method.getBytes(SSHNumbers.charSet));
			buffer.putByte((byte)0);
			buffer.putString(passWord.getBytes(SSHNumbers.charSet));
			TransportPacket packet=new TransportPacket(session);
			packet.setpayLoad(buffer);
			packet.send(oStream);
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void sendAuthenSuccResult(){
		int result=SSHNumbers.SSH_MSG_USERAUTH_SUCCESS;
		Buffer buffer=new Buffer();
		buffer.putByte((byte)result);
		TransportPacket packet=new TransportPacket(session);
		packet.setpayLoad(buffer);
		packet.send(oStream);
	}
	private boolean getAuthenResult(){
		TransportPacket packet=new TransportPacket(session);
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
