import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;


public class DexEdit {

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	/**
	 * Converts byte array to hex string
	 * @param bytes - byte array
	 * @return hex string
	 */
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static long byteAsULong(byte b) {
	    return ((long)b) & 0x00000000000000FFL; 
	}
	
	public static long getUInt32(byte[] bytes) {
	    long value = byteAsULong(bytes[0]) | (byteAsULong(bytes[1]) << 8) | (byteAsULong(bytes[2]) << 16) | (byteAsULong(bytes[3]) << 24);
	    return value;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws IOException {
		// read .dex file to bytes array		
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Input .dex filename\n");
		String filename = br.readLine();
		Path path = Paths.get(filename);
		byte[] dexFileBytes = Files.readAllBytes(path);
		
		// check .dex file maggic
		System.out.print("\nDEX_FILE_MAGIC checkout:\n");
		System.out.print("--------------------------\n");
		byte[] DEX_FILE_MAGIC = { 0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00 };
		for(int i = 0; i < 8; i++) {
			if(dexFileBytes[i] != DEX_FILE_MAGIC[i]) {
				System.out.print(".dex file magic is not valid\n");
				return;
			}
		}
		System.out.print(".dex file Magic Ok\n");
		
		// method's bytes:
		byte[] methodBytes = { 0x13, 0x00, 0x2A, 0x00, 0x0F, 0x00 };
		
		System.out.print("\nSearching for method in .dex file:\n");
		System.out.print("------------------------------------\n");
		// search method in .dex file:
		int methodOffset = -1;
		for(int i = 0; i < dexFileBytes.length; i++) {
			if (i < dexFileBytes.length - 6 && 
					dexFileBytes[i] == methodBytes[0] && 
					dexFileBytes[i + 1] == methodBytes[1] &&
					dexFileBytes[i + 2] == methodBytes[2] && 
					dexFileBytes[i + 3] == methodBytes[3] && 
					dexFileBytes[i + 4] == methodBytes[4] && 
					dexFileBytes[i + 5] == methodBytes[5]) {
				methodOffset = i;
				System.out.print("Method was found, method offset = " + methodOffset + "\n");
				break;
			}
		}
		if(methodOffset == -1) {
			System.out.print("Method wasn't found");
			return;
		}
		
		// Displaying .dex file header:
		System.out.print("\nDisplaying .dex file header:\n");
		System.out.print("------------------------------\n");
		
		// display Adler32 checksum:
		int adler32StartOffset = 8;
		int adler32EndOffset = 12; 
		byte[] checksum = new byte[4];
		for(int i = adler32StartOffset; i < adler32EndOffset; i++) {
			checksum[i - adler32StartOffset] = dexFileBytes[i];
		}
		
		long adler32Checksum = getUInt32(checksum);
		System.out.print("Adler32 checksum of the file = " + adler32Checksum + "\n");
		
		// display SHA1 hash:
		int sha1StartOffset = 12;
		int sha1EndOffset = 32; 	// offset to the end of sha1 in the header
		byte[] sha1 = new byte[sha1EndOffset - sha1StartOffset];
		System.out.print("SHA1 is: ");
		for(int i = sha1StartOffset; i < sha1EndOffset; i++)	{
			sha1[i - sha1StartOffset] = dexFileBytes[i];
			System.out.print(bytesToHex(new byte[] { sha1[i - sha1StartOffset] }) + " ");
		}		
		System.out.println();
		
		System.out.print("\nCompute SHA1 and Adler32 checksum and compare to SHA1 and Adler32 from .dex file:\n");
		System.out.print("-----------------------------------------------------------------------------------\n");
		// Compute SHA1 and compare with SHA1 in .dex file			
		byte[] bytesToHash = new byte[dexFileBytes.length - sha1EndOffset];
		
		for(int i = sha1EndOffset; i < dexFileBytes.length; i++) {
			bytesToHash[i - sha1EndOffset] = dexFileBytes[i];
		}
		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		}
		catch(NoSuchAlgorithmException e) {
	        e.printStackTrace();
		} 
		byte [] sha1Recomputed = md.digest(bytesToHash);
		System.out.print("SHA1:\n");
		boolean isEqual = true;
		for(int i = 0; i < sha1Recomputed.length; i++) {
			System.out.print(bytesToHex(new byte[] { sha1Recomputed[i] }) + " ");
			if(sha1[i] != sha1Recomputed[i])
				isEqual = false;
		}	
		System.out.println();	
		System.out.print("Computed SHA1 is " + ((!isEqual) ? "not " : "") + "equal to .dex file SHA1\n");
		
		// Compute Adler32 checksum and compare to Adler32 checksum in .the header
		System.out.print("\nAdler32 checksum:\n");		
		
		Adler32 adler32 = new Adler32();
		adler32.update(dexFileBytes, adler32EndOffset, dexFileBytes.length - adler32EndOffset);
		long adler32ChecksumRecomputed = adler32.getValue();
		System.out.print(adler32ChecksumRecomputed + "\n");
		System.out.print("Computed adler32 is " + ((adler32Checksum != adler32ChecksumRecomputed) ? "not " : "") + "equal to .dex file SHA1\n");
		
		// modify method in .dex file:
		System.out.print("\nModify method's bytecode:\n");
		System.out.print("---------------------------\n");
		
		byte[] newDexFileBytes = dexFileBytes;
		newDexFileBytes[methodOffset + 2] = 0x09;
		System.out.print("Method has been modified\n");
		
		// compute new SHA1
		byte[] newBytesToHash = new byte[dexFileBytes.length - sha1EndOffset];
		
		for(int i = sha1EndOffset; i < dexFileBytes.length; i++) {
			newBytesToHash[i - sha1EndOffset] = newDexFileBytes[i];
		}		
		byte[] newSha1 = md.digest(newBytesToHash);
		System.out.print("New SHA1:\n");
		for(int i = 0; i < newSha1.length; i++) {
			System.out.print(bytesToHex(new byte[] { newSha1[i] }) + " ");
		}	
		
		// write SHA1 to the header
		for(int i = sha1StartOffset; i < sha1EndOffset; i++) {
			newDexFileBytes[i] = newSha1[i - sha1StartOffset];
		}
		
		// compute new Adler32 checksum
		System.out.print("\nNew Adler32 checksum:\n");
		adler32 = new Adler32();
		adler32.update(newDexFileBytes, adler32EndOffset, newDexFileBytes.length - adler32EndOffset);
		long newAdler32Checksum = adler32.getValue();
		System.out.print(newAdler32Checksum + "\n");
		
		// write adler32 checksum to the header
		int iValue = (int)newAdler32Checksum;
		byte[] array = new byte[4];		
		ByteBuffer buf = ByteBuffer.wrap(array);
		buf.putInt(0, iValue);
		array = buf.array();
		byte[] array2 = new byte[4];
		array2[0] = (byte) ((newAdler32Checksum >> 0) & 0xff);
		array2[1] = (byte) ((newAdler32Checksum >> 8) & 0xff);
		array2[2] = (byte) ((newAdler32Checksum >> 16) & 0xff);
		array2[3] = (byte) ((newAdler32Checksum >> 24) & 0xff);
		
		for(int i = adler32StartOffset; i < adler32EndOffset; i++)
		{
			newDexFileBytes[i] = array2[i - adler32StartOffset];
		}
		
		// check out new adler32 checksum				
		long newAdler32ChecksumCheck = getUInt32(array2);
		System.out.print(newAdler32ChecksumCheck);
		System.out.println();
		System.out.print("Computed new adler32 is " + ((newAdler32Checksum != newAdler32ChecksumCheck) ? "not " : "") + "equal to new .dex file SHA1\n");
		
		// create new file
		FileOutputStream fos = new FileOutputStream("classes.dex");
		fos.write(newDexFileBytes);
		fos.close();
	}
}
