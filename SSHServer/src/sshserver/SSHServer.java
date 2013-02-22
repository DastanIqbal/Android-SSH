package sshserver;
import java.io.*;
import java.net.*;

import sshauthen.ClientAuthen;
import sshsession.SSHSession;
import sshtransport.Buffer;
import sshtransport.TransportPacket;

import keyexchange.*;
import constant.*;
public class SSHServer {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		ServerSocket serverSocket;
		try{
			//Generate server public/private key
			SSHSession.generateServerKey();
			//start listening
			serverSocket=new ServerSocket(2222);
			while(true){
				Socket client=serverSocket.accept();
				ClientThread clThread=new ClientThread(client);
				//create a new thread for each client
				Thread t=new Thread(clThread);
				t.start();
			}
		}
		catch (Exception e){
			e.printStackTrace();
			System.exit(-1);
		}
	}	
}
