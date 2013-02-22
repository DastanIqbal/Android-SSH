package android.ntuan.sshclient;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.text.method.ScrollingMovementMethod;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;

public class DisplayActitivy extends Activity implements OnClickListener {
	EditText edtCommand;
	EditText edtDisplay;
	Button btnSend;
	Intent serviceIntent;
	ScrollView scrollDisplay;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
		setContentView(R.layout.display);
		Intent intent=getIntent();
		Bundle b=intent.getExtras();
		edtCommand=(EditText)findViewById(R.id.editCmd);
		edtDisplay=(EditText)findViewById(R.id.edtDisplay);
		//edtDisplay.setMovementMethod(new ScrollingMovementMethod());
		scrollDisplay=(ScrollView)findViewById(R.id.scrollViewDisplay);
		btnSend=(Button)findViewById(R.id.btnSend);
		btnSend.setOnClickListener(this);
		
		serviceIntent=new Intent(this,SSHClientService.class);
		serviceIntent.putExtras(b);
		if (mService==null){
			startService(serviceIntent);
		}
		mConnection=new MyServiceConnection();
		edtCommand.setText("download /root/test.dat /mnt/sdcard/test.dat");
		//edtCommand.setText("cmd.exe /c dir d:");
		//registerReceiver(mMessageRcver, new IntentFilter("ntuan.sshclient.CONNECT"));
	
	}
	@Override
	protected void onSaveInstanceState(Bundle outState) {
		// TODO Auto-generated method stub
		super.onSaveInstanceState(outState);
		
	}
	@Override
	protected void onStart() {
		// TODO Auto-generated method stub
		super.onStart();
		
	}
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event)
	{
	    if ((keyCode == KeyEvent.KEYCODE_BACK))
	    {
	        mService.clearContent();
	        stopService(serviceIntent);
	    	finish();
	    }
	    return super.onKeyDown(keyCode, event);
	}
	public void onClick(View v) {
		// TODO Auto-generated method stub
		String cmd=edtCommand.getText().toString();
		
		if (mService!=null){
			mService.sendCommand(cmd);
		}
		else{
			startService(serviceIntent);
			bindService(serviceIntent, mConnection,0);
			mService.sendCommand(cmd);
		}		
		edtDisplay.append(" "+cmd);
		//mService.sb.append(" "+cmd);
	}
	@Override
	protected void onResume() {
		// TODO Auto-generated method stub
		super.onResume();
		registerReceiver(mMessageRcver, new IntentFilter("ntuan.sshclient.CONNECT"));
		registerReceiver(mMessageRcver, new IntentFilter("ntuan.sshclient.UPDATE"));
		bindService(serviceIntent, mConnection,0);
	}
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// TODO Auto-generated method stub
		MenuInflater inflater=getMenuInflater();
		inflater.inflate(R.menu.menu, menu);
		return true;
	}
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// TODO Auto-generated method stub
		switch(item.getItemId()){
		case R.id.disconn:
			stopService(serviceIntent);		
			finish();
		}
		return true;
	}
	@Override
	protected void onPause() {
		// TODO Auto-generated method stub
		super.onPause();
		unbindService(mConnection);
		unregisterReceiver(mMessageRcver);
		//stopService(serviceIntent);
	}
	private BroadcastReceiver mMessageRcver=new BroadcastReceiver() {
		
		@Override
		public void onReceive(Context context, Intent intent) {
			// TODO Auto-generated method stub
			if (intent.getAction().equals("ntuan.sshclient.CONNECT")){
				//boolean success=intent.get
				Bundle b=intent.getExtras();
				boolean success=b.getBoolean("connect");
				if (success){
					//edtDisplay.setText("Connect to server sucessfully");
				}
				else{
					//edtDisplay.setText("Connect to server failed");
				}
			}
			if (intent.getAction().equals("ntuan.sshclient.UPDATE")){
				String line=intent.getExtras().getString("data");
				String current=edtDisplay.getText().toString();
				String lastLine="";
				if (!current.equals("")){
					int pos=current.lastIndexOf("\n");
					lastLine=current.substring(pos+1);
					if (pos>0)
						current=current.substring(0,pos);
				}				
				if (lastLine.startsWith("Getting") || lastLine.startsWith("Sending")){
					edtDisplay.setText("");
					edtDisplay.append(current+"\n");
					edtDisplay.append(line);
					scrollDisplay.fullScroll(ScrollView.FOCUS_DOWN);
				}
				else{
					if (edtDisplay.getText().toString().equals(""))
						edtDisplay.append(line);
					else{
						edtDisplay.append("\n"+line);
					}
					scrollDisplay.fullScroll(ScrollView.FOCUS_DOWN);
				}				
			}
		}
	};	
	private SSHClientService mService=null;
    private MyServiceConnection mConnection;
	class MyServiceConnection implements ServiceConnection{

		public void onServiceConnected(ComponentName className, IBinder service) {
			// TODO Auto-generated method stub
			mService=((SSHClientService.LocalBinder)service).getService();
			//edtDisplay.setText(mService.getContent());
			//edtDisplay.scrollTo(0, edtDisplay.getBottom());
			edtDisplay.setText("");
			edtDisplay.append(mService.getContent());
			//scrollDisplay.smoothScrollTo(0,scrollDisplay.getBottom());
			//edtDisplay.scrollBy(0,edtDisplay.getLineHeight()*edtDisplay.getLineCount());
			//scrollDisplay.fullScroll(ScrollView.FOCUS_DOWN);
		}

		public void onServiceDisconnected(ComponentName name) {
			// TODO Auto-generated method stub
			//mService=null;			
		}
    	
    };
}
