#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include<openssl/evp.h>

unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char decryptdata[AES_BLOCK_SIZE];
unsigned char userkey[128];

clock_t start, end;
AES_KEY key, dkey;


void encrypt(char *encoding, char *in, char *out) {
	start = clock();

	FILE *ifp, *ofp;
	if (encoding=="-binary"){
		fopen_s(&ifp, in, "rb");
		fopen_s(&ofp, out, "wb");
	}
	fopen_s(&ifp, in, "r");
	fopen_s(&ofp, out, "w");
	

	static int bytes_read, bytes_write;
	
	while (1) {

		if(encoding=="-base64") decode(ifp, AES_BLOCK_SIZE);
		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
		AES_ecb_encrypt(indata, outdata, &key, AES_ENCRYPT);
		bytes_write = fwrite(outdata, 1, bytes_read, ofp);
		if (encoding== "-base64") encode(ofp, AES_BLOCK_SIZE);
		
		if (bytes_read < AES_BLOCK_SIZE)
			break;
	}

	fclose(ifp);
	fclose(ofp);
	end = clock();
	printf("평문 파일명: %s\n", in);
	printf("암호문 파일명  %s\n", out);
	printf("암호화 걸린시간 : %.3fs\n", (double)(end - start) / CLOCKS_PER_SEC);
}

void decrypt(char *encoding, char *in, char *out) {
	start = clock();
	
	FILE *ifp, *ofp;
	if (encoding=="-binary"){
		fopen_s(&ifp, in, "rb");
		fopen_s(&ofp, out, "wb");
	}
	fopen_s(&ifp, in, "r");
	fopen_s(&ofp, out, "w");

	static int bytes_read, bytes_write;
	while (1) {
		if (encoding== "-base64") decode(ifp, AES_BLOCK_SIZE);
		bytes_read = fread(outdata, 1, AES_BLOCK_SIZE, ifp);
		AES_ecb_encrypt(outdata, decryptdata, &dkey, AES_DECRYPT);
		bytes_write = fwrite(decryptdata, 1, bytes_read, ofp);
		if (encoding=="-base64") encode(ofp, AES_BLOCK_SIZE);

		
		
		//   printf("%s\n", decryptdata);
		if (bytes_read < AES_BLOCK_SIZE)
			break;
	}
	fclose(ifp);
	fclose(ofp);
	end = clock();
	printf("암호문 파일명: %s\n", in);
	printf("복호문 파일명  %s\n", out);

	printf("복호화 걸린시간 : %.3fs\n", (double)(end - start) / CLOCKS_PER_SEC);
}

void dumpString(char *s) { // 키입력 16진수로 변환함수
	char Key[16];
	size_t arraySize = strlen(s) + 1;
	printf("키값 : %s\n", s);

	for (size_t i = 0; i < arraySize - 1; i++){
		sprintf(Key, "\\x%02X", *(s + i));
		strcat(userkey, Key);
	}
}

void choice(char *ch, char *encoding, char *in, char *out){
	if (strcmp(ch , "-enc")==0) encrypt(encoding,in,out);
	else if(strcmp(ch, "-dec")==0) decrypt(encoding, in, out);
}


int main() {
	char *aa[9][15];

	printf("------------------------------------aes 암호화 프로그램-------------------------------------------\n");
	printf("암호화 예시 : Cipher -key [128bit key] -enc [-binary/base64] -in plaintext.txt -out ciphertext.enc\n");
	printf("복호화 예시 : Cipher -key [128bit key] -dec [-binary/base64] -in ciphertext.txt -out plaintext.txt\n");
	printf("커맨드를 입력하세요: \n");
	AES_set_encrypt_key(userkey, 128, &key);
	AES_set_decrypt_key(userkey, 128, &dkey);
	for (int i = 0; i<9; i++){
		scanf("%s", aa[i]);
	}
	dumpString(aa[2]);
	
	choice(aa[3],aa[4],aa[6],aa[8]);
	
	

}
