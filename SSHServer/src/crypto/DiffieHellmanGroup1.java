package crypto;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
public class DiffieHellmanGroup1 {
	static final byte[] g={ 2 };
	static final byte[] p={
	(byte)0x00,
	(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
	(byte)0xC9,(byte)0x0F,(byte)0xDA,(byte)0xA2,(byte)0x21,(byte)0x68,(byte)0xC2,(byte)0x34,
	(byte)0xC4,(byte)0xC6,(byte)0x62,(byte)0x8B,(byte)0x80,(byte)0xDC,(byte)0x1C,(byte)0xD1,
	(byte)0x29,(byte)0x02,(byte)0x4E,(byte)0x08,(byte)0x8A,(byte)0x67,(byte)0xCC,(byte)0x74,
	(byte)0x02,(byte)0x0B,(byte)0xBE,(byte)0xA6,(byte)0x3B,(byte)0x13,(byte)0x9B,(byte)0x22,
	(byte)0x51,(byte)0x4A,(byte)0x08,(byte)0x79,(byte)0x8E,(byte)0x34,(byte)0x04,(byte)0xDD,
	(byte)0xEF,(byte)0x95,(byte)0x19,(byte)0xB3,(byte)0xCD,(byte)0x3A,(byte)0x43,(byte)0x1B,
	(byte)0x30,(byte)0x2B,(byte)0x0A,(byte)0x6D,(byte)0xF2,(byte)0x5F,(byte)0x14,(byte)0x37,
	(byte)0x4F,(byte)0xE1,(byte)0x35,(byte)0x6D,(byte)0x6D,(byte)0x51,(byte)0xC2,(byte)0x45,
	(byte)0xE4,(byte)0x85,(byte)0xB5,(byte)0x76,(byte)0x62,(byte)0x5E,(byte)0x7E,(byte)0xC6,
	(byte)0xF4,(byte)0x4C,(byte)0x42,(byte)0xE9,(byte)0xA6,(byte)0x37,(byte)0xED,(byte)0x6B,
	(byte)0x0B,(byte)0xFF,(byte)0x5C,(byte)0xB6,(byte)0xF4,(byte)0x06,(byte)0xB7,(byte)0xED,
	(byte)0xEE,(byte)0x38,(byte)0x6B,(byte)0xFB,(byte)0x5A,(byte)0x89,(byte)0x9F,(byte)0xA5,
	(byte)0xAE,(byte)0x9F,(byte)0x24,(byte)0x11,(byte)0x7C,(byte)0x4B,(byte)0x1F,(byte)0xE6,
	(byte)0x49,(byte)0x28,(byte)0x66,(byte)0x51,(byte)0xEC,(byte)0xE6,(byte)0x53,(byte)0x81,
	(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
	};
	
	BigInteger e;  // my public key
	byte[] e_array;
	BigInteger f;  // your public key
	BigInteger K;  // shared secret key
	byte[] K_array; 
	private KeyPairGenerator myKpairGen;
	private KeyAgreement myKeyAgree;
	public DiffieHellmanGroup1(){
		try{
			init();
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	public void init() throws Exception{
	    myKpairGen=KeyPairGenerator.getInstance("DH");//get an instance of Diffie-Hellman class
//	    myKpairGen=KeyPairGenerator.getInstance("DiffieHellman");
	    myKeyAgree=KeyAgreement.getInstance("DH");
//	    myKeyAgree=KeyAgreement.getInstance("DiffieHellman");
	}
	public byte[] getE() throws Exception{ //e=g^x%p
	    if(e==null){
	      DHParameterSpec dhSkipParamSpec=new DHParameterSpec(new BigInteger(p), new BigInteger(g));
	      myKpairGen.initialize(dhSkipParamSpec);
	      KeyPair myKpair=myKpairGen.generateKeyPair();//generate key pair
	      myKeyAgree.init(myKpair.getPrivate());//get private key, value x
//	    BigInteger x=((javax.crypto.interfaces.DHPrivateKey)(myKpair.getPrivate())).getX();
	      byte[] myPubKeyEnc=myKpair.getPublic().getEncoded();//calculate e=g^x%p
	      e=((javax.crypto.interfaces.DHPublicKey)(myKpair.getPublic())).getY();
	      e_array=e.toByteArray();
	    }
	    return e_array;
	  } 
	public byte[] getK() throws Exception{
	    if(K==null){
	      KeyFactory myKeyFac=KeyFactory.getInstance("DH");
	      DHPublicKeySpec keySpec=new DHPublicKeySpec(f, new BigInteger(p), new BigInteger(g));
	      PublicKey yourPubKey=myKeyFac.generatePublic(keySpec);
	      myKeyAgree.doPhase(yourPubKey, true);
	      byte[] mySharedSecret=myKeyAgree.generateSecret();
	      K=new BigInteger(mySharedSecret);
	      K_array=K.toByteArray();

	//System.err.println("K.signum(): "+K.signum()+
//			   " "+Integer.toHexString(mySharedSecret[0]&0xff)+
//			   " "+Integer.toHexString(K_array[0]&0xff));

	      K_array=mySharedSecret;
	    }
	    return K_array;
	  } 
	public void setF(byte[] f){ setF(new BigInteger(f)); }
	void setF(BigInteger f){this.f=f;}
}
