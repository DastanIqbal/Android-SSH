package sshtransport;
import java.io.*;
import java.util.Random;

import sshsession.SSHSession;

public class TransportPacket {
	public int packetLength;
	public byte paddingLength;
	public byte[] payLoad;
	public byte[] padding;
	public byte[] mac;
	boolean hasMac=false;
	boolean encrypted=false;
	boolean compressed=false;
	private SSHSession session;
	int[] uncompress_len=new int[1];
	int[] compress_len=new int[1];
	int macSize=0;
	public TransportPacket(SSHSession session){
		this.session=session;
	}
	//public void readWholePacket(InputStream iStream){
	//	if (encrypted==false&&compressed==false&&hasMac=false){
			
	//	}
	//}
	private boolean verifyMAC(DataInputStream iStream,byte[] data) throws Exception{
		mac=new byte[session.HASHC2S.getBlockSize()];
		iStream.readFully(mac);
		session.HASHC2S.update(session.seqIn);
		session.HASHC2S.update(data,0,data.length);
		byte[] checkData=new byte[mac.length];
		session.HASHC2S.doFinal(checkData, 0);
		//session.seqIn++;
		return java.util.Arrays.equals(mac, checkData);		
	}
	public void readPacket(InputStream iStream){
		try{
			if (session.cipherC2S==null) //no encrypted
				readPacket_noEncrypt(iStream);
			else{
				DataInputStream dataStream=new DataInputStream(iStream);
				byte[] firstBlock=new byte[session.cipherBlocksize];
				dataStream.readFully(firstBlock);
				//s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
				session.cipherC2S.update(firstBlock, 0, session.cipherBlocksize, firstBlock, 0);
				packetLength=((firstBlock[0]<<24)&0xff000000)|
				        ((firstBlock[1]<<16)&0x00ff0000)|
				        ((firstBlock[2]<< 8)&0x0000ff00)|
				        ((firstBlock[3]    )&0x000000ff);
				int remaining=packetLength+4-session.cipherBlocksize;
				byte[] data=new byte[packetLength+4];
				System.arraycopy(firstBlock, 0, data, 0,session.cipherBlocksize);
				dataStream.readFully(data, session.cipherBlocksize, remaining);
				session.cipherC2S.update(data, session.cipherBlocksize, remaining, data, session.cipherBlocksize);
				//calculate payLoad Length
				this.paddingLength=data[4];
				int payLoadLength=packetLength-paddingLength-1;
				payLoad=new byte[payLoadLength];
				System.arraycopy(data, 5, payLoad, 0, payLoadLength);
				//System.arraycopy(data, 5+payLoadLength, padding, destPos, length)
				if (session.HASHC2S!=null){
					if (verifyMAC(dataStream,data)!=true){
						System.out.println("MAC not matched");
					}
					else{
						//System.out.println("Correct!!");
					}
				}
				session.seqIn++;
				
				//uncompress
				if (session.inflater!=null){
					//uncompress payload
					uncompress_len[0]=payLoadLength;
					byte[] temp=session.inflater.uncompress(payLoad, 0, uncompress_len);
					payLoadLength=uncompress_len[0];
					payLoad=new byte[payLoadLength];
					System.arraycopy(temp, 0, payLoad, 0, payLoadLength);
				}
			}
			
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void readPacket_noEncrypt(InputStream iStream){
		try{
			DataInputStream dataIstream=new DataInputStream(iStream);
			packetLength=dataIstream.readInt();
			byte[] temp=new byte[packetLength];
			//Must be change when support resume
			dataIstream.readFully(temp);
			paddingLength=temp[0];			
			//payload length=?
			int payloadLength=packetLength-1-paddingLength;
			payLoad=new byte[payloadLength];
			System.arraycopy(temp, 1, payLoad, 0, payloadLength);
			if (session.HASHC2S!=null){
				ByteArrayOutputStream outStream=new ByteArrayOutputStream();
				DataOutputStream dataOut=new DataOutputStream(outStream);
				dataOut.writeInt(packetLength);
				dataOut.write(temp);
				if (verifyMAC(dataIstream,outStream.toByteArray())!=true){
					System.out.println("MAC not matched");
				}
				//must veryfy mac
			}
			session.seqIn++;
		}
		catch (Exception e){
			e.printStackTrace();
			//Must be change when support resume
		}
	}
	public void setpayLoad(byte[] payLoad){
		this.payLoad=payLoad;
	}
	public void setpayLoad(Buffer buffer){
		byte[] data=new byte[buffer.getLength()];
		buffer.getByte(data);
		payLoad=data;
	}
	public byte[] getpayLoad(){
		return payLoad;
	}
	private void calLength(int blocksize){
		//condition: packetLength + 4 mod blocksize =0
		//packetLenth = payLoadLength+paddingLength+1
		int payLoadLength=payLoad.length;
		paddingLength=(byte)(blocksize-((payLoadLength+1+4)%blocksize));
		if (paddingLength<4)
			paddingLength+=blocksize;
		packetLength=payLoadLength+paddingLength+1;
		padding=new byte[paddingLength];
		Random rand=new Random();
		rand.nextBytes(padding);
	}
	private void calLength(){
		calLength(8);//default block size
	}
	private byte[] calMac(byte[] data){
		try{
			byte[] hash=new byte[session.HASHS2C.getBlockSize()];
			session.HASHS2C.update(session.seqOut);
			session.HASHS2C.update(data,0,data.length);
			session.HASHS2C.doFinal(hash,0);
			//session.seqOut++;
			return hash;
		}
		catch (Exception e){
			e.printStackTrace();
			return null;
		}
	}
	public void send(OutputStream stream){
		if (session.cipherS2C==null)
			send_noEncrypt(stream);
		else{
			try{
				
				if (session.deflater!=null){
					compress_len[0]=payLoad.length;
					byte[] temp=session.deflater.compress(payLoad, 0, compress_len);
					payLoad=new byte[compress_len[0]];
					System.arraycopy(temp,0, payLoad, 0, payLoad.length);
				}
				
				calLength(session.cipherBlocksize);
				ByteArrayOutputStream byteStream=new ByteArrayOutputStream();
				DataOutputStream outStream=new DataOutputStream(byteStream);
				outStream.writeInt(packetLength);
				outStream.writeByte(paddingLength);
				outStream.write(payLoad);
				outStream.write(padding);
				byte[] data=byteStream.toByteArray();
				if (session.HASHS2C!=null)
					mac=calMac(data);
				session.cipherS2C.update(data, 0, data.length, data, 0);
				if (session.HASHS2C!=null){
					byte[] finalData=new byte[data.length+mac.length];
					System.arraycopy(data,0, finalData, 0, data.length);
					System.arraycopy(mac,0,finalData, data.length,mac.length);
					stream.write(finalData);
				}
				else
					stream.write(data);
				stream.flush();
				session.seqOut++;
			}
			catch (Exception e){
				e.printStackTrace();
			}
		}
	}
	private void send_noEncrypt(OutputStream stream){
		try{
			if (packetLength==0)
				calLength();
			ByteArrayOutputStream byteStream=new ByteArrayOutputStream();
			DataOutputStream outStream=new DataOutputStream(byteStream);
			outStream.writeInt(packetLength);
			outStream.writeByte(paddingLength);
			outStream.write(payLoad);
			outStream.write(padding);
			byte[] data=byteStream.toByteArray();
			if (session.HASHS2C!=null){
				mac=calMac(data);
				outStream.write(mac);
			}
			session.seqOut++;
			stream.write(byteStream.toByteArray());
			stream.flush();
		}
		catch (IOException e){
			e.printStackTrace();
		}
	}
//	private void sendFully(byte[] data,OutputStream stream){
//		try{
//			int remain=data.length;
//			int sent=0;
//			while (remain>0){
//				stream.write(data, sent, remain);
//				stream.wri
//			}
//		}
//		catch (Exception e){
//			e.printStackTrace();
//		}
//	}
}
