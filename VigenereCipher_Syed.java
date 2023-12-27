package encryption;

import java.util.Arrays;
import java.util.List;


public interface VigenereCipher_Syed {
	
	public final static List<Character> ENGLISH_LOWERCASE_LETTERS_LIST = Arrays.asList('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z');
	public final static List<Character> ENGLISH_UPPERCASE_LETTERS_LIST = Arrays.asList('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z');
	
	//part of pre: plainMessage[i] != null, for i in [0, plainMessage.length)
	//part of pre: plainMessage[i].charAt(j) is in {'a', 'b', 'c', ...,'z'}, for i
	// in [0, plainMessage.length) and j in [0, plainMessage[i].length())
	//part of pre: key != null
	//part of pre: key.length() > 0
	//part of post: rv.charAt(j) is in {'A', 'B', 'C', ..., 'Z'} U {' '}, for j
	// in [0, rv.length())
	public static String encrypt(String[] plainMessage, String key)
	{
		if (key.equals(null) || key.length() == 0) {
			return null;
		}
			
		String cipherMessage = "";
		String singleString = "";
		
		for (int index = 0; index < plainMessage.length; index++) {
			singleString += " " + plainMessage[index];	
		}
		
		cipherMessage += encrypt(singleString.trim(), key);
		return cipherMessage;
	}
	
	//part of pre: plainText != null
	//part of pre: plainText.charAt(j) is in {'a', 'b', 'c', ...'z'}, for j
	// in [0, plainText.length())
	//part of pre: key != null
	//part of pre: key.length() > 0
	//part of post: rv.charAt(j) is in {'A', 'B', 'C', ..., 'Z'}, for j
	// in [0, rv.length())
	public static String encrypt(String plainText, String key){
		String cipherText = "";
		int keyIndex  = 0;	
		char plainTextChar;
		char keyCharIndex;
		int plainTextIndex = 0;
		
		while (plainTextIndex < plainText.length()) {
			plainTextChar = plainText.charAt(plainTextIndex);
			boolean is_Space = false;
			
			if (plainTextChar == ' ') {
				is_Space = true;
			}
			
			if (is_Space) {	
				cipherText += " ";
			}
			
			else {
				keyCharIndex = key.charAt(keyIndex );
				cipherText += getMatrixEntry(plainTextChar, keyCharIndex);
				keyIndex ++;
				if (keyIndex >= key.length()) {
				    keyIndex = 0;
				}
			}
			
			plainTextIndex++;
		}
		
		return cipherText;
	}
	
	//part of pre: encryptedMessage[i] != null, for i in [0, encryptedMessage.length)
	//part of pre: encryptedMessage[i].charAt(j) is in {'A', 'B', 'C', ...,'Z'}, for i
	// in [0, encryptedMessage.length) and j in [0, encryptedMessage[i].length())
	//part of pre: key != null
	//part of pre: key.length() > 0
	//part of post: rv.charAt(j) is in {'a', 'b', 'c', ..., 'z'} U {' '}, for j
	// in [0, rv.length())
	//part of post: left out, but need to express exactly where the spaces are in rv
	public static String decrypt(String[] encryptedMessage, String key)
	{
		String plainMessage = "";
		String singleString = "";
		
		for (int i = 0; i < encryptedMessage.length; i++) {
			singleString += " " + encryptedMessage[i];	
		}
		
		plainMessage += decrypt(singleString, key);
		return plainMessage.trim();
	}
	
	//part of pre: encryptedText != null
	//part of pre: encryptedText.charAt(j) is in {'A', 'B', 'C', ...,'Z'}, for j
	// in [0, encryptedText.length())
	//part of pre: key != null
	//part of pre: key.length() > 0
	//part of post: rv.charAt(j) is in {'a', 'b', 'c', ..., 'z'}, for j in [0, rv.length())
	public static String decrypt(String encryptedText, String key)
	{
		String plainText = "";
		int keyIndex = 0;
		int encryptedTextIndex = 0;
		char plainTextChar;
		char keyCharIndex;
		
		while (encryptedTextIndex < encryptedText.length()) {
			plainTextChar = encryptedText.charAt(encryptedTextIndex);
			boolean empty = false;
			
			if (plainTextChar == ' ') {
				empty = true;
			}
			
			if (empty == true) {	
				plainText += " ";
			}
			
			else {
				keyCharIndex = key.charAt(keyIndex);
				plainText += getColumn(keyCharIndex, plainTextChar);
				keyIndex++;
				
				if (keyIndex >= key.length()) {
				    keyIndex = 0;
				}
				
			}
			
			encryptedTextIndex++;
		}
		
		return plainText;
	}
	
	//part of pre: row is in {'a', 'b', 'c', ...'z'}
	//part of pre: column is in {'a', 'b', 'c', ...'z'}
	//part of post: rv is in {'A', 'B', 'C', ..., 'Z'}
	public static char getMatrixEntry(char row, char column) {
		int rowIndex = ENGLISH_LOWERCASE_LETTERS_LIST.indexOf(row);
		int columnIndex = ENGLISH_LOWERCASE_LETTERS_LIST.indexOf(column);
		int matrixEntryIndex = rowIndex + columnIndex;
		
		if (matrixEntryIndex > 25) {
		    matrixEntryIndex -= 26;
		}	
		
		char matrixEntry = ENGLISH_UPPERCASE_LETTERS_LIST.get(matrixEntryIndex);
		return matrixEntry;
	}
	
	//part of pre: row is in {'a', 'b', 'c', ...'z'}
	//part of pre: matrixEntry is in {'A', 'B', 'C', ..., 'Z'}
	//part of post: rv is in {'a', 'b', 'c', ...'z'}
	public static char getColumn(char row, char matrixEntry)
	{
		int rowIndex = ENGLISH_LOWERCASE_LETTERS_LIST.indexOf(row);
		int matrixEntryIndex = ENGLISH_UPPERCASE_LETTERS_LIST.indexOf(matrixEntry); 
		int columnIndex = rowIndex - matrixEntryIndex;
		
		if (columnIndex < 0) {
		    columnIndex *= -1;
		} 
		
		if (matrixEntryIndex < rowIndex) {
		    columnIndex = 26 - columnIndex;
		}
		
		if (columnIndex > 25) {
		    columnIndex -= 26;
		}	

		char column = ENGLISH_LOWERCASE_LETTERS_LIST.get(columnIndex);
		return column;
	}

}
