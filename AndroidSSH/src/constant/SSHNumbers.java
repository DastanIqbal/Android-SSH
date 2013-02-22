package constant;

public class SSHNumbers {
	 public static String charSet="ISO-8859-1";
	 public static byte SSH_MSG_KEXINIT=20;
	 public static byte SSH_MSG_NEWKEYS=21;
	 public static final int SSH_MSG_KEXDH_INIT=30;
	 public static final int SSH_MSG_KEXDH_REPLY=31;
	 public static final int SSH_MSG_SERVICE_REQUEST=5;
	 public static final int SSH_MSG_SERVICE_ACCEPT=6;
	 public static final int SSH_MSG_USERAUTH_REQUEST=50;
	 public static final int SSH_MSG_USERAUTH_SUCCESS=52;
	 public static final int SSH_MSG_USERAUTH_FAILURE=51;
	 public static final int SSH_MSG_USERAUTH_BANNER=53;
	 
	 /*public static final int SSH_MSG_EXECUTE=100;
	 public static final int SSH_MSG_FILE_DOWNLOAD=110;
	 public static final int SSH_MSG_FILE_DOWNLOAD_DATA=111;
	 public static final int SSH_MSG_HASH_REQUEST=210;
	 public static final int SSH_MSG_HASH_DATA=211;
	 public static final int SSH_MSG_FILE_UPLOAD=120;
	 public static final int SSH_MSG_FILE_UPLOAD_DATA=121;
	 public static final int SSH_MSG_EXECUTE_RESULT=200;*/
      
	 public static final int SSH_MSG_EXECUTE=100;
	 
	 public static final int SSH_MSG_FILE_TRANSFER_DL=101;
	 public static final int SSH_MSG_FILE_TRANSFER_UL=102;
	 public static final int SSH_MSG_FILE_TRANSFER_DIGEST=103; // from destination side to source side
	 public static final int SSH_MSG_FILE_TRANSFER_POINTER=104; //from source side to destination side
	 public static final int SSH_MSG_FILE_TRANSFER_DATA=105;
	 
	 public static final int SSH_MSG_FILE_TRANSFER_SYNC_RESULT=106;
	 
	 
	 public static final int SSH_MSG_EXECUTE_RESULT=200;
	 
	 public static final int DIGEST_CHUNK_SIZE = 10000;
	 public static final int DIGEST_PER_MSG = 1250;
	 public static final int MAX_MSG_SIZE = 20000;

	 public static final int numberofRetry = 10;
	 public static final int delayBetweenRetries=8000;
	 
	 
	 public static final String AuthenserviceName="ssh-userauth";
	 public static final String ConnserviceName="ssh-connection";
	 public static final String method="password";
}
