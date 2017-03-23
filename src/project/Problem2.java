package project;

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Problem2 {
	//initialize an arraylist to store all the 128-byte long encrypted messages.
	public static ArrayList<byte[]> client_byte_list = new ArrayList<byte[]>();
	public static ArrayList<byte[]> server_byte_list = new ArrayList<byte[]>();
	//arraylist to store the arraylists which contain binary strings of the usernames
	public static ArrayList<ArrayList<String>> UserName_Storage = new ArrayList<ArrayList<String>>();
	//arraylist to store the arraylists which contain binary strings of the passwords
	public static ArrayList<ArrayList<String>> PassWord_Storage = new ArrayList<ArrayList<String>>();
	//arraylist to store the label of each message output into the txt file, ie, [CORRECT] or [WRONG].
	public static ArrayList<String> Label = new ArrayList<String>();
	//this 8-bit binary string is used to determine when the username or password string end.
	public static String terminator = String.format("%8s", Integer.toBinaryString((int)' ')).replace(' ', '0');
	//main function
	public static void main(String[] args) {
		//read in the bytes from log files
		//store 128-byte messages into the two arraylist respectively
		readLogFile("ServerLogEnc.dat");
	    readLogFile("ClientLogEnc.dat");
	    
	    //genenrate a comparator which is used to compare with 
	    //the first byte of the (client message XOR server message)
	    //this comparator is used to identify the correct combination of usernames and passwords
		int server1 = (int)'W';
		int client1 = (int)'L';
		String server_s1 = String.format("%8s", Integer.toBinaryString(server1)).replace(' ', '0');
		String client_s1 = String.format("%8s", Integer.toBinaryString(client1)).replace(' ', '0');
		String comparator1 = XOR(server_s1, client_s1);
		
		//this comparator is used to identify the combination of correct username and wrong password
		int server2 = (int)'P';
		int client2 = (int)'L';
		String server_s2 = String.format("%8s", Integer.toBinaryString(server2)).replace(' ', '0');
		String client_s2 = String.format("%8s", Integer.toBinaryString(client2)).replace(' ', '0');
		String comparator2 = XOR(server_s2, client_s2);
		
		//this comparator is used to identify the combination of wrong username and password
		int server3 = (int)'I';
		int client3 = (int)'L';
		String server_s3 = String.format("%8s", Integer.toBinaryString(server3)).replace(' ', '0');
		String client_s3 = String.format("%8s", Integer.toBinaryString(client3)).replace(' ', '0');
		String comparator3 = XOR(server_s3, client_s3);
		
		//for loop to iterate through each 128-byte message in both lists.
		for(int i = 0; i < client_byte_list.size(); i++){
			//process the messages that contain users who have actually logged into the system. 
			//initialize the first byte of each list and xor them to compare with the comparator.
			String client_first_binary_string = byte2binary(client_byte_list.get(i)[0]);
			String server_first_binary_string = byte2binary(server_byte_list.get(i)[0]);
			String xor = XOR(client_first_binary_string, server_first_binary_string);
			
			//processing the message containing correct username and password combination
			if(xor.equals(comparator1)){
				//initialize an arraylist to store the binary strings corresponding to a username
				ArrayList<String> userName = new ArrayList<String>();
				//it is noticed that the first byte of the username started at 
				//the 7th byte of the login message sent by client
				for(int j = 6; j < 128; j++){
					//evaluate the first byte of the username
					if(j == 6){
						//obtain the first byte of the username
						//it is noticed that the corresponding character in the reply message from server is 'E'
						String client_username_firstbyte = byte2binary(client_byte_list.get(i)[j]);
						String server_username_firstbyte = byte2binary(server_byte_list.get(i)[j]);
						String xor_first = XOR(client_username_firstbyte, server_username_firstbyte);
						String username_firstbyte = XOR(xor_first, String.format("%8s", Integer.toBinaryString((int)'E')).replace(' ', '0'));
						userName.add(username_firstbyte);
						continue;
					}
					//evaluate the second byte of the username
					else if(j == 7){
						//obtain the second byte of the username
						//it is noticed that the corresponding character in the reply message from server is a space.
						String client_username_secondbyte = byte2binary(client_byte_list.get(i)[j]);
						String server_username_secondbyte = byte2binary(server_byte_list.get(i)[j]);
						String xor_second = XOR(client_username_secondbyte, server_username_secondbyte);
						String username_secondbyte = XOR(xor_second, terminator);
						//if it is found that second byte obtained is also a space, then that's the end of the username
						if(username_secondbyte.equals(terminator)){
							//obtain the corresponding password
							ArrayList<String> passWord = GetPassword_ForCorrectLogin(client_byte_list.get(i), server_byte_list.get(i),j+1, userName.get(userName.size()-1));
							PassWord_Storage.add(passWord);
							break;
						}
						//else, add the second byte into the username binary string list
						else{
							userName.add(username_secondbyte);
							continue;
						}
					}
					//evaluate the third, fourth....byte of the username
					//it is noticed the XOR of the byte in client sent encrypted message 
					//and the corresponding byte in server sent encrypted reply message
					//is the XOR of U(i) byte of the username and U(i-2) byte of the username
					//since we know first and second byte of the username, it is easy to deduce the rest of the username
					String client_username_byte = byte2binary(client_byte_list.get(i)[j]);
					String server_username_byte = byte2binary(server_byte_list.get(i)[j]);
					String xor_byte = XOR(client_username_byte, server_username_byte);
					String username_byte = XOR(xor_byte, userName.get(userName.size()-2));
					//stops at the point where the space in the encrypted message from client is encountered
					if(username_byte.equals(terminator)){
						//obtain the corresponding password
						ArrayList<String> passWord = GetPassword_ForCorrectLogin(client_byte_list.get(i), server_byte_list.get(i),j+1, userName.get(userName.size()-1));
						PassWord_Storage.add(passWord);
						break;
					}
					else{
						userName.add(username_byte);
					}		
				}
				//add the arraylist storing the username binary strings to UserName_Storage arraylist
				UserName_Storage.add(userName);
				//add [CORRECT] to the label arraylist
				Label.add("[CORRECT]");
			}
			
			//processing the message containing the correct username and wrong password combination
			else if(xor.equals(comparator2)){
				//initialize an arraylist to store the binary strings corresponding to a username
				ArrayList<String> userName = new ArrayList<String>();
				//initialize a temp array to store the characters to be XORed with XOR(encrypted client byte, encrypted server byte)
				char [] temp = new char[122];
				temp[0] = 'R'; temp[1] = 'D'; temp[2] = ' '; temp[3] = 'M'; temp[4] = 'I'; 
				temp[5] = 'S'; temp[6] = 'M'; temp[7] = 'A'; temp[8] = 'T'; temp[9] = 'C'; temp[10] = 'H';
				for(int j = 11; j < temp.length; j++){
					temp[j] = ' ';
				}
				//it is noticed that the first byte of the username start from position 6 of the client encrypted message
				//loop to iterate starting from position 6.
				//Each byte of the username is found by XOR(XOR(encrypted client byte, encrypted server byte), corresponding byte stored in the temp array).
				for(int j = 6; j < 128; j++){
					String client_byte = byte2binary(client_byte_list.get(i)[j]);
					String server_byte = byte2binary(server_byte_list.get(i)[j]);
					String xor_byte = XOR(client_byte, server_byte);
					String username_byte = XOR(xor_byte, String.format("%8s", Integer.toBinaryString((int)temp[j-6])).replace(' ', '0'));
					if(username_byte.equals(terminator)){
						//stop when space is encountered and start obtaining the password
						ArrayList<String> passWord = GetPassword_ForIncorrectLogin(client_byte_list.get(i), server_byte_list.get(i), j+1, temp);
						PassWord_Storage.add(passWord);
						break;
					}
					else{
						userName.add(username_byte);
					}
				}
				UserName_Storage.add(userName);
				Label.add("[INCORRECT]");
			}		
			
			//processing the message containing the wrong username
			//the method used in this segment of code is similar to the above "else if" code segment
			else if(xor.equals(comparator3)){
				//initialize an arraylist to store the binary strings corresponding to a username
				ArrayList<String> userName = new ArrayList<String>();
				//initialize a temp array to store the characters to be XORed with the XOR(encrypted client byte, encrypted server byte)
				char [] temp = new char[122];
				temp[0] = 'E'; temp[1] = 'C'; temp[2] = 'T'; temp[3] = ' '; temp[4] = 'U'; temp[5] = 'S'; 
				temp[6] = 'E'; temp[7] = 'R'; temp[8] = 'N'; temp[9] = 'A'; temp[10] = 'M'; temp[11] = 'E';
				for(int j = 12; j < temp.length; j++){
					temp[j] = ' ';
				}
				for(int j = 6; j < 128; j++){
					String client_byte = byte2binary(client_byte_list.get(i)[j]);
					String server_byte = byte2binary(server_byte_list.get(i)[j]);
					String xor_byte = XOR(client_byte, server_byte);
					String username_byte = XOR(xor_byte, String.format("%8s", Integer.toBinaryString((int)temp[j-6])).replace(' ', '0'));
					if(username_byte.equals(terminator)){
						ArrayList<String> passWord = GetPassword_ForIncorrectLogin(client_byte_list.get(i), server_byte_list.get(i), j+1, temp);
						PassWord_Storage.add(passWord);
						break;
					}
					else{
						userName.add(username_byte);
					}
				}
				UserName_Storage.add(userName);
				Label.add("[INCORRECT]");
			}
			
			
			//else, move to the next message
			else
				continue;
			
		}
		//store the label, username and password to a txt file
		write2UserNameFile(UserName_Storage, PassWord_Storage, Label);
	}
	
	//utility function to read in the log files
	public static void readLogFile(String fileName){
		byte[] byte_stream = new byte[128];
		ArrayList<Byte> temp_storage = new  ArrayList<Byte>();
		try{
			FileInputStream fileInput = new FileInputStream(fileName);
			DataInputStream input = new DataInputStream (fileInput);
			while(input.available() > 0){
				byte temp = input.readByte();
				temp_storage.add(temp);
			}
		}
		catch (IOException e){
			e.printStackTrace();
		}
		for(int i = 0; i < temp_storage.size()/128;i++){
			for(int j = 0; j < 128; j++){
				byte_stream[j] = temp_storage.get(i*128+j);
			}
			if(fileName.equals("ServerLogEnc.dat"))
				server_byte_list.add(byte_stream);
			else if(fileName.equals("ClientLogEnc.dat"))
				client_byte_list.add(byte_stream);
			byte_stream = new byte[128];
		}
	}
	
	//utility function to convert a byte to a binary string
	public static String byte2binary (byte a){
		String s1 = String.format("%8s", Integer.toBinaryString(a & 0xFF)).replace(' ', '0');
		return s1;
	}
	
	//utility function to conduct XOR operation on two binary strings
	public static String XOR(String str1, String str2){
		String xor = String.format("%8s",Integer.toBinaryString(Integer.parseInt(str1, 2) ^ Integer.parseInt(str2, 2))).replace(' ', '0');
		return xor;
	}

	//function to obtain the password corresponding to the username for correct login
	public static ArrayList<String> GetPassword_ForCorrectLogin(byte[] cbyte_list, byte[] sbyte_list, int index, String usrname_last_byte){
		ArrayList<String> temp_password = new ArrayList<String>();
		//it is noticed that the first byte of password can be obtained with 
		//XOR(XOR(client_encrypted_byte, server_encrypted_byte), last byte of user name obtained)) 
		String client_pw1_byte = byte2binary(cbyte_list[index]);
		String server_pw1_byte = byte2binary(sbyte_list[index]);
		String xor_byte = XOR(client_pw1_byte, server_pw1_byte);
		String password_firstbyte = XOR(xor_byte, usrname_last_byte);
		//store the first byte into temp_password arraylist
		temp_password.add(password_firstbyte);
		//iterate through the remaining byte of the client encrypted bytes to get the remaining bytes of the password
		//the reamining byte of the server encrypted bytes are spaces.
		//the loop breaks when XOR(XOR(client_encrypted_byte, server_encrypted_byte), binary string of space)) = binary string of space
		for(int i = index+1; i < cbyte_list.length; i++){
			String client_pw_byte = byte2binary(cbyte_list[i]);
			String server_pw_byte = byte2binary(sbyte_list[i]);
			String xor1_byte = XOR(client_pw_byte, server_pw_byte);
			String password_byte = XOR(xor1_byte, terminator);
			if(password_byte.equals(terminator))
				break;
			temp_password.add(password_byte);
		}
		//return the arraylist storing the binary strings of each character in the password
		return temp_password;
	}
	
	//since the way to obtain password for incorrect login differs from that for correct login, a separate function is used
	//function to obtain the password corresponding to the username for incorrect login
	public static ArrayList<String> GetPassword_ForIncorrectLogin(byte[] cbyte_list, byte[] sbyte_list, int index, char[] temp){
		ArrayList<String> temp_password = new ArrayList<String>();
		//iterate through all the remaining bytes of the client encrypted message 
		//starting from the position that is immediately after the space behind the last byte of username
		//similarly, each password byte is found by XOR(XOR(client_encrypted_byte, server_encrypted_byte), corresponding bytes stored in temp char))
		//the loop breaks when XOR(XOR(client_encrypted_byte, server_encrypted_byte), corresponding bytes stored in temp char)) = space
		for(int i = index; i < cbyte_list.length; i++){
			String client_byte = byte2binary(cbyte_list[i]);
			String server_byte = byte2binary(sbyte_list[i]);
			String xor_byte = XOR(client_byte, server_byte);
			String password_byte = XOR(xor_byte, String.format("%8s", Integer.toBinaryString((int)temp[i-6])).replace(' ', '0'));
			if(password_byte.equals(terminator))
				break;
			temp_password.add(password_byte);
		}
		//return the arraylist storing the binary strings of each character in the password
		return temp_password;
	}
	
	//utility function to write usernames and password to a txt file
	public static void write2UserNameFile(ArrayList<ArrayList<String>> temp1, ArrayList<ArrayList<String>> temp2, ArrayList<String> temp3){
		try {
            FileWriter fileWriter =  new FileWriter("Problem2.txt");
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            for(int k = 0; k < temp1.size(); k++){
            	String username = "";
            	String password = "";
    			for(int i = 0;  i < temp1.get(k).size();i++){
    				username += (char)Integer.parseInt(temp1.get(k).get(i), 2);
    			}
    			for(int i = 0;  i < temp2.get(k).size();i++){
    				password += (char)Integer.parseInt(temp2.get(k).get(i), 2);
    			}
                bufferedWriter.write(temp3.get(k)+" "+ username +" "+password);
                bufferedWriter.newLine();
             }
             bufferedWriter.close(); 
             }
		catch(FileNotFoundException ex) {
        	ex.printStackTrace();               
        }
        catch(IOException ex) {
        	ex.printStackTrace();
        }	
	}
	
}
