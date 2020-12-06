//g++ main.cpp base64.h base64.cpp AES.h AES.cpp

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include <ctime>
#include <vector>

#include "AES.h"
#include "base64.h"	

using namespace std;

int main(){
	string file_name, key, out_file_name;
	AES aes(256);
	
	cout << "FILE CIPHER (AES_256)" << endl;
	cout << "1) crypt file" << endl;
	cout << "2) decrypt file" << endl;
	cout << "3) generate key (base64)" << endl;
	cout << ">>> ";
	
	int x;
	cin >> x;
	cout << endl << endl;
	
	switch(x){
		case 1:
			//crypt file
			cout << "\nfile name: ";
			cin >> file_name;
			cout << "output file name: ";
			cin >> out_file_name;
			
			cout << "key(base64): ";
			cin >> key;
			
			aes.CryptFile(file_name, out_file_name, key);
			break;
			
		case 2:
			//decrypt file
			cout << "\nfile name: ";
			cin >> file_name;
			cout << "output file name: ";
			cin >> out_file_name;
			
			cout << "key(base64): ";
			cin >> key;
			
			aes.DecryptFile(file_name, out_file_name, key);
			break;
		
		case 3:
			//generate key
			key = aes.GenerateKey();
			cout << "\nThis is your new key: " << key << endl;
			break;
		
		default:
			cout << "WTF!!" << endl;
			break;
	}
	
	cout << "\nCIAO ;)\n";
	
	return 0;
}
