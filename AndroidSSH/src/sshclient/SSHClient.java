package sshclient;
import java.net.*;
import java.security.MessageDigest;
import java.util.Currency;

import android.ntuan.sshclient.SSHClientService;
import constant.*;
import java.io.*;

import crypto.FileDigest;

import sshauthen.ClientAuthen;
import sshsession.session;
import sshtransport.Buffer;
import sshtransport.TransportPacket;

import keyexchange.keyExchange;
public class SSHClient {
	//static String ipAdd="127.0.0.1";
	//static String ipAdd=null;
	//public static byte[] current_cookies;
	private InputStream inStream;
	int time=0;
	private OutputStream outStream;
	private Socket clientSock=null;
	private boolean stop=false;
	public void intterupt(){
		stop=true;
		close();
	}
	private SSHClientService sshService=null;
	/*public SSHClient(String ipAddress, String userName, String password){
		session.hostName=ipAddress;
		session.userName=userName;
		session.password=password;
	}*/
	public SSHClient(String ipAddress, String userName, String password,SSHClientService service){
		session.hostName=ipAddress;
		session.userName=userName;
		session.password=password;
		this.sshService=service;
	}
	public boolean isConnected(){
		if (clientSock==null)
			return false;
		return clientSock.isConnected();
	}
	public void close(){
		try {
			clientSock.close();
			clientSock=null;
		}
		catch (Exception e){
			
		}
	}
	public boolean reconnect(){
		if (stop==true)
			return false;
		session.clear();
		boolean flag=false;
		int i=0;
		while (flag==false && i<SSHNumbers.numberofRetry && !stop){
			flag= connect();
			if (flag==false){
				sshService.sendString("Reconnection attemp "+(i+1)+" failed.");
				sshService.sendString("Continue to reconnect after "+(SSHNumbers.delayBetweenRetries/1000)+" seconds");
				try {
					Thread.sleep(SSHNumbers.delayBetweenRetries);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				i++;
			}
			else{
				sshService.sendString("Reconnection is successful");	
				stop=false;
			}
		}
		stop=false;
		return flag;
	}
	public boolean connect(){
		try{
			clientSock=new Socket(session.hostName, 2222);
			session.clear();
			//session.hostName=session;
			inStream=clientSock.getInputStream();
			outStream=clientSock.getOutputStream();
			BufferedReader reader=new BufferedReader(new InputStreamReader(inStream,SSHNumbers.charSet));
			String line=reader.readLine();
			
			session.serverID=line.getBytes(SSHNumbers.charSet);
			line="SSH-2.0-MySSHClient_1.0\r\n";
			session.clientID=line.substring(0,line.length()-2).getBytes(SSHNumbers.charSet);
			
			DataOutputStream oStream=new DataOutputStream(outStream);
			oStream.write(line.getBytes(SSHNumbers.charSet));
			oStream.flush();
			
			keyExchange keyEx=new keyExchange(new DataInputStream(inStream),oStream);
			keyEx.doKeyExchange();
			ClientAuthen authen=new ClientAuthen(session.userName,session.password,inStream,oStream);
			
			boolean flag= authen.doAuthen();
			if (flag==true)
				recvPrompt();
			return flag;
		}
		catch (Exception e){
			e.printStackTrace();
			//close();
			return false;
		}
	}
	private void recvPrompt(){
		try{
			TransportPacket packet=new TransportPacket();
			packet.readPacket(inStream);
			Buffer buffer=new Buffer(packet.getpayLoad());
			try {
				sshService.currentPrompt=new String(buffer.getString(),SSHNumbers.charSet);
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				
			}
			int flag=buffer.getByte();
			if (flag==0){
				sshService.sendString("No such file or directory");
			}
			sshService.sendString(sshService.currentPrompt,false);
		}
		catch (SocketException e){
			
		}
	}
	
	public void sendCommand(String cmd){
		try{
			session.currentCommand=cmd;
			String[] tem = cmd.trim().replaceAll("  "," ").split(" ");
			TransportPacket packet=new TransportPacket();
			Buffer buffer=new Buffer();
			//System.out.println(tem[0]);
			if( tem[0].equals("download")) {
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_DL);
			} else if ( tem[0].equals("upload")) {
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_UL);
			} else {
				//buffer.putByte((byte)SSHNumbers.SSH_MSG_EXECUTE);
				sendExecCommand(cmd);
				return;
			}
				
			buffer.putString(cmd.getBytes(SSHNumbers.charSet));
			packet.setpayLoad(buffer);
			packet.send(outStream);
			// handling download/upload commands
			if( tem[0].equals("download")) {
				sendDigest(tem[2]); //what is tem[2]: destination file				
				//no resuming
				//getData(tem[2],0);
			} else if ( tem[0].equals("upload") ) {
				getDigest(tem[1]); //source file
			}
			//sshService.sendString(sshService.currentPrompt,false);
		}
		catch (SocketException e){
			this.sshService.sendString("Connection to servier is lost");
			this.sshService.sendString("Waiting for reconnection ...");
			if (reconnect()==false){
				this.sshService.sendString("Reconnection failed, please connect to this server later");
			}
			else{
				this.sshService.sendString("Resuming file transfer");
				sendCommand(session.currentCommand);
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	
	public void sendExecCommand(String cmd){
		try{
			TransportPacket packet=new TransportPacket();
			sshtransport.Buffer buffer=new sshtransport.Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_EXECUTE);
			buffer.putString(cmd.getBytes(SSHNumbers.charSet));
			packet.setpayLoad(buffer);
			packet.send(outStream);
			if (cmd.startsWith("cd")){
				recvPrompt();
			}
			else{
				getExecResult();
				sshService.sendString(sshService.currentPrompt,false);
			}
		}
		catch (SocketException e){
			this.sshService.sendString("Connection to servier is lost");
			this.sshService.sendString("Waiting for reconnection ...");
			if (reconnect()==false){
				this.sshService.sendString("Reconnection failed, please connect to this server later");
			}
			else{
				this.sshService.sendString("Please re-execute your previous command");
			}
			//sshService.sendString(sshService.currentPrompt,false);
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void getExecResult(){
		try{
			boolean cont=true;
			do{
				TransportPacket packet=new TransportPacket();
				packet.readPacket(inStream);
				Buffer buffer=new Buffer(packet.getpayLoad());
				int MsgCode=buffer.getByte();
				assert(MsgCode==SSHNumbers.SSH_MSG_EXECUTE_RESULT);
				int check=buffer.getByte();
				if (check!=1)
					cont=false;
				if (check!=-1){
					byte[] temp=buffer.getString();
					String data=new String(temp,SSHNumbers.charSet);
					//System.out.println(data);
					this.sshService.sendString(data);
				}
			}while(cont==true);
		}
		catch (SocketException e){
			this.sshService.sendString("Connection to servier is lost");
			this.sshService.sendString("Please re-execute your previous command");
			this.sshService.sendString("Waiting for reconnection ...");
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
		
	//Moloud part
	private void sendDigest(String dst) throws SocketException{
		try{
			//sendData(dst,0);
			//return;
			RandomAccessFile D = new RandomAccessFile(dst, "rw"); // open destination file to send digest
			MessageDigest md = MessageDigest.getInstance("MD5");
			
			int Dsz = (int)D.length(); //size of destination file
			int nChunk = (int)Math.ceil((double)Dsz/SSHNumbers.DIGEST_CHUNK_SIZE); // number of chunks which destination has
			int nMsg = (int)Math.ceil((double)nChunk/SSHNumbers.DIGEST_PER_MSG); //number of messages to send the digests of chunks
			
			if (nMsg>0)
				sshService.sendString("Sending hash codes to server");
			for (int i = 0; i < nMsg - 1; i++) //for all digest messages except last one which is not complete
			{
				TransportPacket packet=new TransportPacket(); //create a new packet
				Buffer buffer=new Buffer(); 
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_DIGEST); //set the MSG type flag
				buffer.putByte((byte)1); // check for the last msg to send digests

				for (int j = 0; j < SSHNumbers.DIGEST_PER_MSG; j++) // for each chunk calculate the digest and add it to the message
				{
					byte bArr[] = new byte[SSHNumbers.DIGEST_CHUNK_SIZE]; 
					D.readFully(bArr); //by reading the pointer of file automatically moves forward
					buffer.putByte(md.digest(bArr)); // add the byte array of digested chunk
				}
				packet.setpayLoad(buffer);
				packet.send(outStream);
			}
			// for the last packet
			TransportPacket packet=new TransportPacket();
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_DIGEST);
			buffer.putByte((byte)0); // check for last packet of digest series

			boolean stay = true;
			for (int j = 0;stay && j < SSHNumbers.DIGEST_PER_MSG; j++)
			{
				byte bArr[] = new byte[SSHNumbers.DIGEST_CHUNK_SIZE];
				int len = SSHNumbers.DIGEST_CHUNK_SIZE;
				if (len > (int)(D.length() - D.getFilePointer()))
				{
					len = (int)(D.length() - D.getFilePointer());
					stay = false;
				}
				
				D.readFully(bArr, 0, len);
				buffer.putByte(md.digest(bArr));
			}
			
			packet.setpayLoad(buffer);
			packet.send(outStream);	
			
			getPointer(dst);
		}
		catch (SocketException e){
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void getDigest(String src) throws SocketException{
		try{
			//getData(dst, pointer);
			RandomAccessFile S = new RandomAccessFile(src, "rw");
			byte[] bArr = new byte[SSHNumbers.DIGEST_CHUNK_SIZE];
			MessageDigest md = MessageDigest.getInstance("MD5");
			sshService.sendString("Getting hash codes from server");
			boolean cont=true;
			int pointer = 0;
			do{
				TransportPacket packet=new TransportPacket();
				packet.readPacket(inStream);
				Buffer buffer=new Buffer(packet.getpayLoad());
				int MsgCode=buffer.getByte();
				assert(MsgCode==SSHNumbers.SSH_MSG_FILE_TRANSFER_DIGEST);
				int check=buffer.getByte();
				
				byte[] dstArr = new byte[16];
				int ch = buffer.getSize() - buffer.getOffSet();
				while (ch > 0 && cont)
				{
					
					buffer.getByte(dstArr);
					
					int len = bArr.length;
					if (len > S.length()-S.getFilePointer()) len = (int)(S.length()-S.getFilePointer());
					S.readFully(bArr, 0, len);
					
					if ( md.isEqual(md.digest(bArr), dstArr) == false )
					{
						cont = false;
					} else pointer = pointer + 1;
					ch = buffer.getSize() - buffer.getOffSet();
				}
				if (check==0)
					cont=false;
			}while(cont==true);
			S.close();
			sendPointer(src, pointer);
		}
		catch (SocketException e){
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	
	private void sendPointer(String src, int point) throws SocketException{
		try{
			System.out.println("pointer: " + point);
			TransportPacket packet=new TransportPacket();
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_POINTER);
			buffer.putInt(point);
			packet.setpayLoad(buffer);
			packet.send(outStream);
			sendData(src, point);
		}
		catch (SocketException e){
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void getPointer(String dst) throws SocketException{
		try{
			TransportPacket packet=new TransportPacket();
			packet.readPacket(inStream);
			Buffer buffer=new Buffer(packet.getpayLoad());
			int MsgCode=buffer.getByte();
			assert(MsgCode==SSHNumbers.SSH_MSG_FILE_TRANSFER_POINTER);
			int pointer = buffer.getInt();
			getData(dst, pointer);
		}
		catch (SocketException e){
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void sendData(String src, int pointer) throws SocketException{
		try{
			RandomAccessFile S = new RandomAccessFile(src, "rw");
			S.seek(pointer * SSHNumbers.DIGEST_CHUNK_SIZE);
			long current=pointer*SSHNumbers.DIGEST_CHUNK_SIZE;	
			while (S.length() - S.getFilePointer() > 0)
			{
				TransportPacket packet=new TransportPacket();
				Buffer buffer=new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_DATA);
				
				int len = SSHNumbers.MAX_MSG_SIZE;
				if (len > (int)(S.length() - S.getFilePointer())) 
				{
					len = (int)(S.length() - S.getFilePointer());
					buffer.putByte((byte)0);
				}
				else 
				{
					buffer.putByte((byte)1);
				}
				
				byte[] bArr = new byte[len];
				
				S.readFully(bArr);
				current+=len;
				buffer.putByte(bArr);
				packet.setpayLoad(buffer);
				packet.send(outStream);
				sshService.sendString("Sending file "+src+": "+current+" bytes");
			}
			S.close();
			sshService.sendString("Finish sending file "+src);
		}
		catch (SocketException e){
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void getData(String dst, int pointer) throws SocketException{
		RandomAccessFile D=null;
		
		try{
			D = new RandomAccessFile(dst, "rw");
			D.seek(pointer * SSHNumbers.DIGEST_CHUNK_SIZE);
			boolean cont = true;
			long current=pointer*SSHNumbers.DIGEST_CHUNK_SIZE;
			do{
				TransportPacket packet=new TransportPacket();
				packet.readPacket(inStream);
				Buffer buffer=new Buffer(packet.getpayLoad());
				int MsgCode=buffer.getByte();
				assert(MsgCode == SSHNumbers.SSH_MSG_FILE_TRANSFER_DATA);
				int check=buffer.getByte();
				if (check==0)
					cont=false;
				
				int len = buffer.getSize() - buffer.getOffSet();
				byte[] tem = new byte[len];
				current+=len;
				/*if (current>1*1024*1024 && time==0){
					close();//interupt at 10MB
					time++;
				}*/
				buffer.getByte(tem);
				//D.write(tem);
				D.write(tem, 0, len);
				sshService.sendString("Getting file "+dst+": "+current+" bytes");
			} while (cont);
			D.close();
			sshService.sendString("Finish downloading file "+dst);
		}
		catch (SocketException e){
			try {
				D.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				
			}
			throw e;
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}

}
