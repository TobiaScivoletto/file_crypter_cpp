/*
programma che cifra e decifra i file
g++ main.cpp base64.h base64.cpp AES.h AES.cpp
*/

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include <ctime>
#include <vector>

#include "AES.h"
#include "base64.h"

#define KEY_LEN 256
#define BUFFER_LEN 32	

using namespace std;

int crypt_file(string, string);
int decrypt_file(string, string, string);
string generate_key();

int main(){
	string file_name, key, out_file_name;
	
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
			
			cout << "key(base64): ";
			cin >> key;
			
			crypt_file(file_name, key);
			break;
			
		case 2:
			//decrypt file
			cout << "\nfile name: ";
			cin >> file_name;
			cout << "output file name: ";
			cin >> out_file_name;
			
			cout << "key(base64): ";
			cin >> key;
			
			decrypt_file(file_name, out_file_name, key);
			break;
		
		case 3:
			//generate key
			key = generate_key();
			cout << "\nThis is your new key: " << key << endl;
			break;
		
		default:
			cout << "WTF!!" << endl;
			break;
	}
	
	cout << "\nCIAO ;)\n";
	
	return 0;
}

int crypt_file(string file_name, string key_str){
	//decodifico la chiave da base64 a unsigned char
	unsigned char key[BUFFER_LEN];
	vector<BYTE> key_vector = base64_decode(key_str);
	
	int ii = 0;
	for(auto i = key_vector.begin(); i != key_vector.end(); ++i){
		key[ii] = *i;
		ii++;
	}
	
	//cifro il file
	AES aes(KEY_LEN);
	
	ifstream f_in(file_name, ios::binary );
    ofstream f_out(file_name + ".crypt", ios::binary );
	
	unsigned char * buffer_plain = new unsigned char[BUFFER_LEN];
	unsigned char * buffer_cipher;
	unsigned int out_len = 0;
	
	while(!f_in.eof()){
		//crypt
		f_in.read(reinterpret_cast<char *>(buffer_plain), BUFFER_LEN);
		buffer_cipher = aes.EncryptECB(buffer_plain, BUFFER_LEN, key, out_len);
		f_out.write(reinterpret_cast<const char *>(buffer_cipher), out_len);
	}
	
	f_in.close();
	f_out.close();
	return 0;
}


int decrypt_file(string file_name, string file_name_out, string key_str){
	//decodifico la chiave da base64 a unsigned char
	unsigned char key[BUFFER_LEN];
	vector<BYTE> key_vector = base64_decode(key_str);
	
	int ii = 0;
	for(auto i = key_vector.begin(); i != key_vector.end(); ++i){
		key[ii] = *i;
		ii++;
	}
	
	//cifro il file
	AES aes(KEY_LEN);
	
	ifstream f_in(file_name, ios::binary );
    ofstream f_out(file_name_out, ios::binary );
	
	unsigned char * buffer_plain = new unsigned char[BUFFER_LEN];
	unsigned char * buffer_cipher;
	unsigned int out_len = 0;
	
	while(!f_in.eof()){
		//crypt
		f_in.read(reinterpret_cast<char *>(buffer_plain), BUFFER_LEN);
		buffer_cipher = aes.DecryptECB(buffer_plain, BUFFER_LEN, key);
		f_out.write(reinterpret_cast<const char *>(buffer_cipher), BUFFER_LEN);
	}
	
	f_in.close();
	f_out.close();
	
	return 0;
}


string generate_key(){
	string key_64;
	vector<BYTE> key;
	
	//genero i byte casuali
	srand(time(0));
	for(int i=0; i<BUFFER_LEN; i++){
		key.push_back((unsigned char) rand() % 256);
	}
	
	//converto in base64 la chiave
	key_64 = base64_encode(&key[0], key.size());
	
	return key_64;
}
