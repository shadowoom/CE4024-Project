package project;

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Problem1 {
    //initialize an arraylist to store all the 128-byte long encrypted messages.
	public static ArrayList<byte[]> client_byte_list = new ArrayList<byte[]>();
	public static ArrayList<byte[]> server_byte_list = new ArrayList<byte[]>();
	//arraylist to store the arraylists which contain binary strings of the usernames
	public static ArrayList<ArrayList<String>> UserName_Storage = new ArrayList<ArrayList<String>>();
	//the main function
	public static void main(String[] args) {
		//read in the bytes from log files
		//store 128-byte messages into the two arraylist respectively
		readLogFile("ServerLogEnc.dat");
		readLogFile("ClientLogEnc.dat");
		
		//genenrate a comparator which is used to compare with 
	    //the first byte of the (client message XOR server message)
		int server_frist = (int)'W';
		int client_first = (int)'L';
		String s1 = String.format("%8s", Integer.toBinaryString(server_frist)).replace(' ', '0');
		String s2 = String.format("%8s", Integer.toBinaryString(client_first)).replace(' ', '0');
		String comparator = XOR(s1, s2);
		
		//for loop to iterate through each 128-byte message in both lists.
		for(int i = 0; i < client_byte_list.size(); i++){
			//initialize an arraylist to store the binary strings corresponding to a username
			ArrayList<String> userName = new ArrayList<String>();
			
			//this 8-bit binary string is used to determine when the username string end.
			String terminator = String.format("%8s", Integer.toBinaryString((int)' ')).replace(' ', '0');
			
			//process the messages that contain users who have actually logged into the system. 
			//initialize the first byte of each list and xor them to compare with the comparator.
			String client_first_binary_string = byte2binary(client_byte_list.get(i)[0]);
			String server_first_binary_string = byte2binary(server_byte_list.get(i)[0]);
			String xor = XOR(client_first_binary_string, server_first_binary_string);
			
			//if equal, start processing
			if(xor.equals(comparator)){
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
						if(username_secondbyte.equals(terminator))
							break;
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
					if(username_byte.equals(terminator))
						break;
					else{
						userName.add(username_byte);
					}		
				}
				//add the arraylist storing the username binary strings to UserName_Storage arraylist
				UserName_Storage.add(userName);
			}
			
			//if not equal, continue to the next message
			else
				continue;
		}
		//write the usernames to a txt file
		write2UserNameFile(UserName_Storage);		
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
	
	//utility function to write usernames to a txt file
	public static void write2UserNameFile(ArrayList<ArrayList<String>> temp){
		try {
            FileWriter fileWriter =  new FileWriter("Problem1.txt");
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            for(int k = 0; k < temp.size(); k++){
            	String username = "";
    			for(int i = 0;  i < temp.get(k).size();i++){
    				username += (char)Integer.parseInt(temp.get(k).get(i), 2);
    			}
                bufferedWriter.write(username);
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
