package android.ntuan.sshclient;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import sshclient.*;
public class SSHClientService extends Service {
	SSHClient sshClient;
	PowerManager pm = null;
	boolean isRunning=false;
	StringBuilder sb;
	public String currentPrompt;
	Thread tRunningCommand=null;
	public class LocalBinder extends Binder {
        SSHClientService getService() {
            return SSHClientService.this;
        }
    }
	private final IBinder mBinder = new LocalBinder();
	@Override
	public IBinder onBind(Intent intent) {
		// TODO Auto-generated method stub
		return mBinder;
	}
	public void sendCommand(String cmd){
		//sshClient.sendExecCommand(cmd);
		final String cmmand=cmd;
		sb.append(cmd+"\n");
		tRunningCommand=new Thread(new Runnable() {
			
			public void run() {
				// TODO Auto-generated method stub
				WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK|PowerManager.ACQUIRE_CAUSES_WAKEUP, "My Tag");
				wl.acquire();
				long t1=readtotalByte();
				long time1=System.currentTimeMillis();
				//sshClient.sendExecCommand(cmmand);
				sshClient.sendCommand(cmmand);
				long t2=readtotalByte();
				long time2=System.currentTimeMillis();
				//sendString("total bytes="+(t2-t1)+"\n");
				//sendString("time="+((time2-time1)/1000)+" seconds\n");
				wl.release();
				sendString(currentPrompt,false);
			}
		});
		tRunningCommand.start();
	}
	@Override
	public void onCreate() {
		// TODO Auto-generated method stub
		super.onCreate();
		sb=new StringBuilder();
		//String userName=(String) b.get("username");
		//String password=(String) b.get("password");
	}
	@Override
	public void onStart(Intent intent, int startId) {
		// TODO Auto-generated method stub
		super.onStart(intent, startId);
		if (isRunning)
			return;
		pm=(PowerManager) getSystemService(Context.POWER_SERVICE);
		isRunning=true;
		Bundle b=intent.getExtras();
		String userName=(String) b.get("username");
		String password=(String) b.get("password");
		String ipAdd=(String) b.get("ipadd");
		sshClient=new SSHClient(ipAdd, userName, password,this);
		if (!sshClient.isConnected()){
			Thread t=new Thread(new ConnectThread());
			t.start();
		}
	}
	@Override
	public void onDestroy() {
		// TODO Auto-generated method stub
		super.onDestroy();
		isRunning=false;
		sshClient.intterupt();
		//sshClient.close();		
		//tRunningCommand.interrupt();
	}
	//send String to activity
	public void sendString(String line, boolean endLine){
		Intent broadcast=new Intent("ntuan.sshclient.UPDATE");
		Bundle b=new Bundle();
		b.putString("data",line);
		broadcast.putExtras(b);
		sendBroadcast(broadcast);
		if (!line.startsWith("Sending") && !line.startsWith("Getting")){
			sb.append(line);
			if (endLine)
				sb.append("\n");
		}
	}
	public void sendString(String line){
		sendString(line,true);
	}
	public String getContent(){
		return sb.toString();
	}
	public void clearContent(){
		sb=new StringBuilder();
	}
	private long readtotalByte(){
		try{
			FileInputStream t=new FileInputStream("/sys/class/net/wlan0/statistics/rx_bytes");
			BufferedReader reader=new BufferedReader(new InputStreamReader(t));
			String line=reader.readLine();
			long rx=Long.parseLong(line);
			t=new FileInputStream("/sys/class/net/wlan0/statistics/tx_bytes");
			reader=new BufferedReader(new InputStreamReader(t));
			line=reader.readLine();
			long tx=Long.parseLong(line);
			return tx+rx;
		}
		catch (IOException e){
			return 0;
		}		
	}
	class ConnectThread implements Runnable{

		public void run() {
			// TODO Auto-generated method stub
			WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK|PowerManager.ACQUIRE_CAUSES_WAKEUP, "My Tag");
			wl.acquire();
			boolean succes=sshClient.connect();
			Intent broadcast=new Intent("ntuan.sshclient.CONNECT");
			Bundle b=new Bundle();
			if (succes){				
				//b.putBoolean("connect", true);
				//broadcast.putExtra("connect",true);
				//sendString("Connect to server successfully");
			}
			else{
				//b.putBoolean("connect", false);
				//
				sendString("Connect to server failed");
			}
			broadcast.putExtras(b);
			sendBroadcast(broadcast);
			wl.release();
		}		
	}
}
