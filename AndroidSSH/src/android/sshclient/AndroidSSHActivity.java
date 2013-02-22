package android.ntuan.sshclient;

import sshsession.session;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;

public class AndroidSSHActivity extends Activity implements OnClickListener {
    /** Called when the activity is first created. */
    EditText edtserverAdd;
    EditText edtUsername;
    EditText edtPassword;
    Button btnConnect;
    CheckBox chkCompress;
	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        edtserverAdd = (EditText)findViewById(R.id.editServerIP);
        edtUsername = (EditText)findViewById(R.id.editUserName);
        edtPassword = (EditText)findViewById(R.id.editPassword);
        btnConnect = (Button)findViewById(R.id.btnConnect);
        btnConnect.setOnClickListener(this);
        chkCompress=(CheckBox)findViewById(R.id.chkCompress);
        edtserverAdd.setText("138.23.38.176");
        edtUsername.setText("root");
        edtPassword.setText("123456");
    }

	public void onClick(View v) {
		// TODO Auto-generated method stub
		if (chkCompress.isChecked())
			session.useCompression=true;
		else
			session.useCompression=false;
		Intent intent=new Intent(this,DisplayActitivy.class);
		Bundle b=new Bundle();
		b.putString("ipadd",edtserverAdd.getText().toString());
		b.putString("username",edtUsername.getText().toString());
		b.putString("password",edtPassword.getText().toString());
		intent.putExtras(b);
		startActivity(intent);
	}
}