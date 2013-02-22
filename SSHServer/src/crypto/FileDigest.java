package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;

public class FileDigest {
	public static byte[][] calFileDigest(String fileName){
		try{
			File file=new File(fileName);
			FileInputStream inStream=new FileInputStream(file);
			ArrayList<byte[]> list=new ArrayList();
			byte[] data=new byte[2000];
			int byteRead=0;
			MessageDigest msgDigest=MessageDigest.getInstance("SHA");
			while((byteRead=inStream.read(data))!=-1){
				if (byteRead<2000){//fill 0 padding to data array for hashing
					for (int i=byteRead;i<data.length;i++){
						data[i]=0;
					}
				}
				msgDigest.update(data);
				byte[] digest=msgDigest.digest();
				list.add(digest);
				msgDigest.reset();
			}
			byte[][] result=new byte[list.size()][];
			result=list.toArray(result);
			return result;
		}
		catch (IOException e){
			return null;
		}
		catch (Exception e){
			return null;
		}		
	}
	public static int compareHash(byte[][] source, byte[][] dest){
		int min=source.length;
		if (min>dest.length)
			min=dest.length;
		for (int i=0;i<min;i++){
			if (identical(source[i], dest[i])==false){
				return i;
			}
		}
		if (source.length==dest.length)
			return -1;//two files are identical
		return min;		
	}
	private static boolean identical(byte[] source,byte[] dest){
		for (int i=0;i<source.length;i++){
			if (source[i]!=dest[i])
				return false;
		}
		return true;
	}
}
