package sshserver;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.util.ArrayList;

import keyexchange.keyExchange;
import sshauthen.ClientAuthen;
import sshsession.SSHSession;
import sshtransport.Buffer;
import sshtransport.TransportPacket;
import constant.SSHNumbers;
import java.io.*;

import crypto.FileDigest;

public class ClientThread implements Runnable{
	Socket clientSock;
	SSHSession session;
	InputStream iStream;
	OutputStream oStream;
	String currentDir;
	public ClientThread(Socket cl){
		clientSock=cl;
	}
	@Override
	public void run() {
		// TODO Auto-generated method stub
		String hello="SSH-2.0-MySSHServer_1.0";
		try{
			session=new SSHSession();
			iStream=clientSock.getInputStream();
			oStream=clientSock.getOutputStream();
			session.serverID=hello.getBytes(SSHNumbers.charSet);
			ByteArrayOutputStream arrOutStr=new ByteArrayOutputStream();
			DataOutputStream dataOutStream=new DataOutputStream(arrOutStr);
			dataOutStream.write((hello+"\r\n").getBytes(SSHNumbers.charSet));
			byte[] temp=arrOutStr.toByteArray();
			clientSock.getOutputStream().write(temp);
			//Finish sending hello packet
			//read hello packet from the client
			BufferedReader reader=new BufferedReader(new InputStreamReader(clientSock.getInputStream(),SSHNumbers.charSet));
			String line=reader.readLine();//we need to save this information, for encryption
			session.clientID=line.getBytes(SSHNumbers.charSet);
			//create new key exchange class
			keyExchange keyEx=new keyExchange(clientSock.getInputStream(),clientSock.getOutputStream(), session);
			keyEx.doKeyExchange();
			ClientAuthen authen=new ClientAuthen(clientSock.getInputStream(),clientSock.getOutputStream(), session);
			authen.doAuthen();
			currentDir=getUserDir(session.userName);
			sendPrompt(true);
			//get currentDirectory base on userName
			//read /etc/passwd file
			//for now, just assumed /root
			
			//ready for the connection layer
			while (true){
				try{
					receiveCommand();
				}
				catch (SocketException e){
					//disconnected with client
					clientSock.close();
					System.out.println("Client disconnected");
					break;
					//exit the while (true) loop
				}
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private String getHostName(){
		try{
			Runtime runtime=Runtime.getRuntime();
			Process p=runtime.exec("hostname -s");
			InputStream inStream=p.getInputStream();
			BufferedReader reader=new BufferedReader(new InputStreamReader(inStream));
			String line=null;
			line=reader.readLine();
			reader.close();
			return line;
		}
		catch (Exception e){
			return null;
		}		
	}
	private String getPrompt(){
		//username@hostname path
		String path=currentDir;
		if (!currentDir.endsWith("/")){
			currentDir+="/";
		}
		currentDir=currentDir.replaceAll("//","/");
		if (currentDir.equals(getUserDir(session.userName)) || currentDir.equals(getUserDir(session.userName)+"/")){
			path="~";
		}
		String prompt="["+session.userName+"@"+getHostName()+" "+path+"]";
		return prompt;
	}
	private void sendPrompt(boolean flag) throws SocketException{
		TransportPacket packet=new TransportPacket(session);
		Buffer buffer=new Buffer();
		try {
			buffer.putString(getPrompt().getBytes(SSHNumbers.charSet));
			byte result=0;
			if (flag==true)
				result=1;
			buffer.putByte(result);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		packet.setpayLoad(buffer);
		packet.send(oStream);
	}
	private String getUserDir(String userName){
		try{
			BufferedReader reader=new BufferedReader(new InputStreamReader(new FileInputStream("/etc/passwd")));
			String line=null;
			while ((line=reader.readLine())!=null){
				if (line.startsWith(userName+":")){
					String homeDir=line.split(":")[5];
					return homeDir;
				}
			}
			return null;
		}
		catch (Exception e){
			return null;
		}
	}
	private void receiveCommand() throws SocketException{
		TransportPacket packet=new TransportPacket(session);
		packet.readPacket(iStream);
		Buffer buffer=new Buffer(packet.getpayLoad());
		int MsgCode=buffer.getByte();
		String Commd=null;
		try {
			Commd = new String(buffer.getString(),SSHNumbers.charSet);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Commd=Commd.trim().replaceAll("  "," ");
		String[] tem = Commd.split(" ");
		switch (MsgCode){
		case SSHNumbers.SSH_MSG_EXECUTE:			
			receiveExecCommand(Commd);
			break;
		case SSHNumbers.SSH_MSG_FILE_TRANSFER_DL:
			tem[1]=tem[1].replaceAll("~", getUserDir(session.userName)+"/");
			tem[1]=tem[1].replaceAll("\\./",currentDir+"/");
			if (!tem[1].startsWith("/")){
				tem[1]=currentDir+"/"+tem[1];
			}
			tem[1]=tem[1].replaceAll("//","/");
			getDigest(tem[1]);
			break;
		case SSHNumbers.SSH_MSG_FILE_TRANSFER_UL:
			tem[2]=tem[2].replaceAll("~", getUserDir(session.userName)+"/");
			tem[2]=tem[2].replaceAll("\\./",currentDir+"/");
			if (!tem[2].startsWith("/")){
				tem[2]=currentDir+"/"+tem[2];
			}
			tem[2]=tem[2].replaceAll("//","/");
			sendDigest(tem[2]);
			break;
		/*case SSHNumbers.SSH_MSG_HASH_REQUEST:
			receiveHashRequest(Commd);
			break;
		case SSHNumbers.SSH_MSG_FILE_DOWNLOAD:
			//file download processing here
			receiveDownloadCommand(Commd);
			break;
		case SSHNumbers.SSH_MSG_FILE_UPLOAD:
			//file upload processing here
			break;*/		
		}
	}
	private void receiveExecCommand(String Commd) throws SocketException{
		try {
			Commd=Commd.replaceAll("~", getUserDir(session.userName)+"/");
			//Commd.replaceAll("./",currentDir+"/");
			Commd=Commd.replaceAll("//", "/");
			if (Commd.startsWith("cd ")){
				String temp=Commd.split(" ")[1];
				//temp=temp.replaceAll("~", getUserDir(session.userName)+"/");
				//temp=temp.replaceAll("//","/");
				if (!temp.endsWith("/"))
					temp+="/";
				try{
					File file=new File(temp);
					if (file.isDirectory()){
						currentDir=temp;
						sendPrompt(true);
					}
					else{
						sendPrompt(false);
					}
				}
				catch (Exception e){
					sendPrompt(false);
				}
				return;
			}
			Runtime runtime=Runtime.getRuntime();
			if (!session.userName.equals("root"))
				Commd="sudo -u "+session.userName+" "+Commd;
			Process p=runtime.exec(Commd,null,new File(currentDir));
			//Process p=runtime.exec(Commd);
			InputStream commandInput=p.getInputStream();
			BufferedReader reader=new BufferedReader(new InputStreamReader(commandInput));
			String line=null, nextline=null;
			line=reader.readLine();
			Buffer buffer=null;
			TransportPacket packet=new TransportPacket(session);
			while (line!=null){
				nextline = reader.readLine();
				buffer = new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_EXECUTE_RESULT);
				
				//if(nextline != null)
				//{
					buffer.putByte((byte)1);
					
				//} else {
					//buffer.putByte((byte)0);
				//}
				buffer.putString(line.getBytes(SSHNumbers.charSet));
				packet.setpayLoad(buffer);
				packet.send(oStream);
				line = nextline;
			}
			InputStream errStream=p.getErrorStream();
			reader=new BufferedReader(new InputStreamReader(errStream));
			line=nextline=null;
			line=reader.readLine();
			buffer=null;
			packet=new TransportPacket(session);
			while (line!=null){
				nextline = reader.readLine();
				buffer = new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_EXECUTE_RESULT);
				
				if(nextline != null)
				{
					buffer.putByte((byte)1);
					
				} else {
					buffer.putByte((byte)0);
				}
				buffer.putString(line.getBytes(SSHNumbers.charSet));
				packet.setpayLoad(buffer);
				packet.send(oStream);
				line = nextline;
			}
			if (buffer==null){
				buffer=new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_EXECUTE_RESULT);
				buffer.putByte((byte)-1);
				packet.setpayLoad(buffer);
				packet.send(oStream);
			}
			
			p.waitFor();
			//int exitCode=p.exitValue();			
		} 
		catch (SocketException e){
			throw e;
			//throw back IOException to let the function run() detect Client disconnected
		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			//general Exception, not IOException
			e.printStackTrace();
		}
	}
	/*private void receiveHashRequest(String fileName){
		if (fileName.contains(":")){
			fileName=fileName.split(":",2)[1];
		}
		byte[][] result=FileDigest.calFileDigest(fileName);
		Buffer buffer=new Buffer();
		buffer.putByte((byte)SSHNumbers.SSH_MSG_HASH_DATA);
		buffer.putInt(result.length);
		for (int i=0;i<result.length;i++){
			buffer.putString(result[i]);
		}
		TransportPacket packet=new TransportPacket(session);
		packet.setpayLoad(buffer);
		packet.send(oStream);
	}
	private void receiveDownloadCommand(String cmd){
		String[] arguments=cmd.split(" ");
		if (arguments.length>4){
			return;
		}
		//source file: at this SSH server
		// username@hostname:filename
		// username@ipaddress:filename
		// hostname:filename
		String fileName=arguments[1].split(":",2)[1];
		if (!fileName.startsWith("/")){
			fileName=currentDir+fileName;
			fileName.replaceAll("//","/");
		}
		if (arguments.length==4){
			downloadResume(fileName, Long.parseLong(arguments[3]));
		}
		else{
			//from scratch
			downloadFromScratch(fileName);
		}
	}
	private void downloadResume(String fileName, long skip){
		File file;
		try{
			file=new File(fileName);
			RandomAccessFile fStream=new RandomAccessFile(file,"r");
			long remains=skip;
			while (remains>0){
				int temp=0;
				if (remains>Integer.MAX_VALUE)
					temp=Integer.MAX_VALUE;
				else
					temp=(int)remains;
				remains-=temp;
				fStream.skipBytes(temp);
			}
			long fileLength=file.length()-skip;
			
			long totalByteRead=0;
			byte[] data=new byte[2000];
			int byteRead=0;
			//packet structure: MsgCode, EOF, error code,data
			while ((byteRead=fStream.read(data))!=-1 && totalByteRead<fileLength){
				totalByteRead+=byteRead;
				byte eof=0;
				if (totalByteRead==fileLength){
					eof=1;
				}
				Buffer buffer=new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_DOWNLOAD_DATA);
				buffer.putByte(eof);
				buffer.putByte((byte)0);//no error
				buffer.putString(data,0,byteRead);
				TransportPacket packet=new TransportPacket(session);
				packet.setpayLoad(buffer);
				packet.send(oStream);
			}
		}
		catch (IOException e){
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_DOWNLOAD_DATA);
			buffer.putByte((byte)0);//not end of file
			buffer.putByte((byte)1);// error
			TransportPacket packet=new TransportPacket(session);
			packet.send(oStream);
		}
	}
	
	private void downloadFromScratch(String fileName){
		File file;
		try{
			file=new File(fileName);
			FileInputStream fStream=new FileInputStream(file);
			long fileLength=file.length();
			long totalByteRead=0;
			byte[] data=new byte[2000];
			int byteRead=0;
			//packet structure: MsgCode, EOF, error code,data
			while ((byteRead=fStream.read(data))!=-1 && totalByteRead<fileLength){
				totalByteRead+=byteRead;
				byte eof=0;
				if (totalByteRead==fileLength){
					eof=1;
				}
				Buffer buffer=new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_DOWNLOAD_DATA);
				buffer.putByte(eof);
				buffer.putByte((byte)0);//no error
				buffer.putString(data,0,byteRead);
				TransportPacket packet=new TransportPacket(session);
				packet.setpayLoad(buffer);
				packet.send(oStream);
			}
		}
		catch (IOException e){
			Buffer buffer=new Buffer();
			buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_DOWNLOAD_DATA);
			buffer.putByte((byte)0);//not end of file
			buffer.putByte((byte)1);// error
			TransportPacket packet=new TransportPacket(session);
			packet.send(oStream);
		}
	}*/
	//Moloud part
		private void sendDigest(String dst) throws SocketException{
			try{
				RandomAccessFile D = new RandomAccessFile(dst, "rw"); // open destination file to send digest
				MessageDigest md = MessageDigest.getInstance("MD5");
				
				int Dsz = (int)D.length(); //size of destination file
				int nChunk = (int)Math.ceil((double)Dsz/SSHNumbers.DIGEST_CHUNK_SIZE); // number of chunks which destination has
				int nMsg = (int)Math.ceil((double)nChunk/SSHNumbers.DIGEST_PER_MSG); //number of messages to send the digests of chunks
				
				for (int i = 0; i < nMsg - 1; i++) //for all digest messages except last one which is not complete
				{
					TransportPacket packet=new TransportPacket(session); //create a new packet
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
					packet.send(oStream);
				}
				// for the last packet
				TransportPacket packet=new TransportPacket(session);
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
				packet.send(oStream);	
				
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
				RandomAccessFile S = new RandomAccessFile(src, "rw");
				byte[] bArr = new byte[SSHNumbers.DIGEST_CHUNK_SIZE];
				MessageDigest md = MessageDigest.getInstance("MD5");
				
				boolean cont=true;
				int pointer = 0;
				do{
					TransportPacket packet=new TransportPacket(session);
					packet.readPacket(iStream);
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
				TransportPacket packet=new TransportPacket(session);
				Buffer buffer=new Buffer();
				buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_POINTER);
				buffer.putInt(point);
				packet.setpayLoad(buffer);
				packet.send(oStream);
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
				TransportPacket packet=new TransportPacket(session);
				packet.readPacket(iStream);
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
							
				while (S.length() - S.getFilePointer() > 0) //while still have data
				{
					TransportPacket packet=new TransportPacket(session);
					Buffer buffer=new Buffer();
					buffer.putByte((byte)SSHNumbers.SSH_MSG_FILE_TRANSFER_DATA);
					
					int len = SSHNumbers.MAX_MSG_SIZE; //34000? max data length
					if (len > (int)(S.length() - S.getFilePointer())) //if the total data can be sent in 1 packet
					{
						len = (int)(S.length() - S.getFilePointer());
						buffer.putByte((byte)0); //last packet
					}
					else 
					{
						buffer.putByte((byte)1);
					}
					
					byte[] bArr = new byte[len];
					
					S.readFully(bArr);
					buffer.putByte(bArr);
					packet.setpayLoad(buffer);
					packet.send(oStream);
				}
				S.close();
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
				
				do{
					TransportPacket packet=new TransportPacket(session);
					packet.readPacket(iStream);
					Buffer buffer=new Buffer(packet.getpayLoad());
					int MsgCode=buffer.getByte();
					assert(MsgCode == SSHNumbers.SSH_MSG_FILE_TRANSFER_DATA);
					int check=buffer.getByte();
					if (check==0)
						cont=false;
					
					int len = buffer.getSize() - buffer.getOffSet();
					byte[] tem = new byte[len];
					buffer.getByte(tem);
					//D.write(tem);
					D.write(tem, 0, len);
				} while (cont);
				D.close();
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