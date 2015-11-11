#include <iostream>
#include <stdlib.h>
#include <string>
#include <vector>
#include <math.h>
#include <windows.h>  
#include <fstream> 
#define SIZE 64 
using namespace std;
void DES_CBC_DE(char *plaintext_original,int *ciphertext,int *iv);

int main()
{	
	FILE *fp  = NULL;    // source file handler
	FILE *out = NULL;    // target file handler
	BITMAPFILEHEADER FileHeader;  
    BITMAPINFOHEADER InfoHeader;  
    unsigned int  ImageX, ImageY; 
    unsigned char *image_s = NULL; // source image array
    unsigned char *image_t = NULL; // target image array
	char image_sc[65];
	int image_ti[64];
	int iv[]={1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0};
//	int iv[]={0,0,0,0,1,1,0,0,1,0,0,0,1,1,1,0,1,1,0,1,1,0,0,0,0,0,0,0,1,1,0,1,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,1,0,0,0,0,1,1,0,1,1,1,0,1,1}; 
	fp = fopen("Encryption.bmp", "rb");  
 	out = fopen("Decryption.bmp", "wb");  
 	if (fp == NULL) {
		printf("fopen fp error\n");
      	return -1;
	}
	/* 先讀取檔頭資訊 */  
  	fread(&FileHeader, sizeof(BITMAPFILEHEADER), 1, fp);  
  	fread(&InfoHeader, sizeof(BITMAPINFOHEADER), 1, fp);  
  
  	fwrite (&FileHeader , 1 , sizeof(BITMAPFILEHEADER) , out );  
  	fwrite (&InfoHeader , 1 , sizeof(BITMAPINFOHEADER) , out );  
  
  	/* 確定格式 */  
  	if( FileHeader.bfType != 'MB' )  {
		printf("FileHeader.bfType = 'MB'\n");
      	return -1;
	}
  	if( InfoHeader.biCompression != 0 )  {
		printf("InfoHeader.biCompression = 0\n");
      	return -1;
	} 
  	if( InfoHeader.biBitCount != 24 )  {
		printf("InfoHeader.biBitCount = 24\n");
      	return -1;
	}
  	/* 取得圖寬及圖高 */  
  	ImageX = InfoHeader.biWidth;  
  	ImageY = InfoHeader.biHeight;  
  	printf("ImageX:%d\n",ImageX);  
  	printf("ImageY:%d\n",ImageY);  
 	image_s = (unsigned char *)malloc((size_t)ImageX * ImageY * 3);
	image_t = (unsigned char *)malloc((size_t)ImageX * ImageY * 3);
	fread(image_s, sizeof(unsigned char), (size_t)(long)ImageX * ImageY * 3, fp);
	
	int len=(size_t)ImageX * ImageY * 3;
	int image_sp=0,image_tp=0;

	for(int i=0;i<len;i++){//i=what byte of bmp datas, len=length(byte of bmp data)

	if(i%8!=7){
		for(int k=128;k;k>>=1){
		k&image_s[i]?image_sc[image_sp]='1':image_sc[image_sp]='0';
		image_sp++;
		
		}
	}
	else{
		for(int k=128;k;k>>=1){
		k&image_s[i]?image_sc[image_sp]='1':image_sc[image_sp]='0';
		image_sp++;
		}
		image_sc[image_sp]='\0';
		//printf("image_sc %d \n%s\n",i+1,image_sc);
		DES_CBC_DE(image_sc,image_ti,iv);
		image_sp=0;
		unsigned char temp=0;
		
		for(int j=0;j<64;j++){
			if(j%8!=7)
			temp+=image_ti[j]*pow(2,7-(j%8));
			else if(j%8==7){
				temp+=image_ti[j]*pow(2,7-(j%8));
				image_t[image_tp]=temp;
				//printf("%u\n",image_t[image_tp]);
				image_tp++;
				temp=0;
			}
		}
	 
	}
	
		
	}
	fwrite (image_t, sizeof(unsigned char), (size_t)(long)ImageX * ImageY * 3 , out);
    fclose(fp);  
    fclose(out); 
	system("pause"); 
    return 0;
    } 
   
void DES_CBC_DE(char *plaintext_original,int *ciphertext,int *iv){
	vector<int> plaintext(SIZE);
    vector<int> key(SIZE);
    vector<int> IV(SIZE);
    vector<int> IPtext(SIZE);
	vector<int> Lstring(SIZE/2);
	vector<int> Rstring(SIZE/2);
	vector<int> PC1(56);
	vector<int> storeString(SIZE/2);
	vector<int> keyLstring(28);
	vector<int> keyRstring(28);
	vector<int> ShiftLeftKey1(28);
	vector<int> ShiftLeftKey2(28);
	vector<int> newkey(56);
	vector<int> PC2(48);
	vector<int> expansion(48);
	vector<int> xortext(48);
	vector<int> stext(32);
    vector<int> Ciphertext(64); 
	vector<int> FPtext(64);
	vector<int> Ptext(32);

	int value=0;
	int count=0;
    int InitialPermutation[]= {
            58, 50, 42, 34, 26, 18, 10,  2,
            60, 52, 44, 36, 28, 20, 12,  4,
            62, 54, 46, 38, 30, 22, 14,  6,
            64, 56, 48, 40, 32, 24, 16,  8,
            57, 49, 41, 33, 25, 17,  9,  1,
            59, 51, 43, 35, 27, 19, 11,  3,
            61, 53, 45, 37, 29, 21, 13,  5,
            63, 55, 47, 39, 31, 23, 15,  7
	 };	 
	 int FinalPermutation[]= {
        	40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25	 
	 };
	 int PC_1[]={
           57, 49, 41, 33, 25, 17,  9, 1,
		   58, 50, 42, 34, 26, 18, 10, 2,
		   59, 51, 43, 35, 27, 19, 11, 3,
		   60, 52, 44, 36, 63, 55, 47,39,
		   31, 23, 15,  7, 62, 54, 46,38,
		   30, 22, 14,  6, 61, 53, 45,37,
		   29, 21, 13,  5, 28, 20, 12, 4
  	 };
	 int PC_2[]={
	       14, 17, 11, 24,  1,  5,  3, 28,
		   15,  6, 21, 10, 23, 19, 12,  4,
		   26,  8, 16,  7, 27, 20, 13,  2,
	       41, 52, 31, 37, 47, 55, 30, 40,
		   51, 45, 33, 48, 44, 49, 39, 56,
		   34, 53, 46, 42, 50, 36, 29, 32
	 };
	 int Expansion []={
	 	32,  1,  2,  3,  4,  5,
	 	 4,  5,  6,  7,  8,  9,
	 	 8,  9, 10, 11, 12, 13,
	 	12, 13, 14, 15, 16, 17,
	 	16, 17, 18, 19, 20, 21,
	 	20, 21, 22, 23, 24, 25,
	 	24, 25, 26, 27, 28, 29,
	 	28, 29, 30, 31, 32,  1
	 };
	 int sbox[8][4][16] = {
            /* S1 */
            {
            	{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            	{ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
             	{ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
             	{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}          	
			},
 		
            /* S2 */
            {
            	{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            	{ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
             	{ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
             	{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}          	
			},
            /* S3 */
            {
            	{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            	{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
             	{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
             	{ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}          	
			},
            /* S4 */
            {
            	{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            	{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
             	{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
             	{ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}            	
			},
            /* S5 */
            {
            	{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            	{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
             	{ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
             	{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}            	
			},
            /* S6 */
            {
            	{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            	{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
             	{ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
             	{ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}          	
			},
            /* S7 */
            {
            	{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            	{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
             	{ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
             	{ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}          	
			},
            /* S8 */
            {
            	{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            	{ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
             	{ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
             	{ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}           	
			}  
 	};
 	int Permutation[] = {
        	    16,  7, 20, 21,
    	        29, 12, 28, 17,
                 1, 15, 23, 26,
                 5, 18, 31, 10,
                 2,  8, 24, 14,
            	32, 27,  3,  9,
            	19, 13, 30,  6,
            	22, 11,  4, 25
	 };
	int k[]= {1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1, 1,0,1,0, 1,1,1,1};
    for(int i = 0; i < plaintext.size(); i++) {
        plaintext[i]=(int)plaintext_original[i] - '0';
        
        key[i]=k[i];
    }

 	//Plaintext do after Initial Permutation 
	for(int i = 0; i < SIZE; i++){
		IPtext[i]=plaintext[InitialPermutation[i]-1];
	}
	//Plaintext拆成左邊32個字串  右邊32個字串 
	for(int i = 0; i < SIZE/2; i++){
		Lstring[i]=IPtext[i+(SIZE/2)];
		Rstring[i]=IPtext[i];
	}
	//KEY do after PC-1
	for(int i = 0; i <PC1.size(); i++){
		PC1[i]=key[PC_1[i]-1];
	}
	//KEY拆成左邊28個字串 右邊28個字串
	for(int i = 0; i < PC1.size()/2; i++){
		keyLstring[i]=PC1[i];
		keyRstring[i]=PC1[i+(PC1.size()/2)];
	}
	int srk1[16][28];
	int srk2[16][28];
	for(int R=1;R<=16;R++){
		if(R==1 || R==2 || R==9 || R==16){

			for(int i=0;i<27;i++){
			srk1[R-1][i]=keyLstring[i+1];
			srk2[R-1][i]=keyRstring[i+1];
			}			
			srk1[R-1][27]=keyLstring[0];
		    srk2[R-1][27]=keyRstring[0];			
		}
		else{
			for(int i=0;i<26;i++){
			srk1[R-1][i]=keyLstring[i+2];
			srk2[R-1][i]=keyRstring[i+2];
			}			
			srk1[R-1][26]=keyLstring[0];
			srk2[R-1][26]=keyRstring[0];
			srk1[R-1][27]=keyLstring[1];
			srk2[R-1][27]=keyRstring[1];
		}
		for(int i=0;i<28;i++) keyLstring[i]=srk1[R-1][i];
		for(int i=0;i<28;i++) keyRstring[i]=srk2[R-1][i];
	}
	//16ROUND
	for(int R=16;R>=1;R--){
		//Key Schedue
		storeString.assign(Lstring.begin(),Lstring.end());		

		//組合成第i個key 
		for(int i = 0; i < 28; i++){
			newkey[i]=srk1[R-1][i];
			newkey[i+28]=srk2[R-1][i];
		}
		//KEY do after PC-2
		for(int i = 0; i <PC2.size(); i++){
			PC2[i]=newkey[PC_2[i]-1];
		}
		//Rstring do after Expansion
		for(int i = 0; i <expansion.size(); i++){
			expansion[i]=Lstring[Expansion[i]-1];
		}
		//do XOR in F function
		for(int i = 0; i <xortext.size(); i++){
			xortext[i]=expansion[i] xor PC2[i];
		}
		//DO s-Box
		int rowValue=0,columnValue=0,x=0,y=0,z=0,s=0;
		int Tobinanry[4]={0,0,0,0};
		for(int i=0;i<8;i++){
			rowValue=(xortext[x]*2)+(xortext[x+5]*1);
			columnValue=(xortext[x+1]*8)+(xortext[x+2]*4)+(xortext[x+3]*2)+(xortext[x+4]*1);
			s=sbox[i][rowValue][columnValue];
			while(s!=0){
				Tobinanry[3-y]=s%2;
				s/=2;
				y++;
			}			 	
			for(int j=0;j<4;j++){
				stext[z++]=Tobinanry[j];
				Tobinanry[j]=0;
			}
			x+=6;
			y=0;
		}
		//Do Permutation
		for(int i = 0; i < Ptext.size(); i++){
			Ptext[i]=stext[Permutation[i]-1];
		}
		//L-R switch
		//do XOR in switch
		for(int i = 0; i <Rstring.size(); i++){
			Lstring[i]=Ptext[i] xor Rstring[i];
		}
		Rstring.assign(storeString.begin(),storeString.end());
	}
	//Ciphertext do after Final Permutation 
	for(int i=0;i<32;i++){
		FPtext[i]=Lstring[i];
		FPtext[i+32]= Rstring[i];
	}
	for(int i=0;i<64;i++){
		Ciphertext[i]=FPtext[FinalPermutation[i]-1];
	 
	}
		//Plaintext do after IV
	for(int i = 0; i < SIZE; i++){
		ciphertext[i]=iv[i] xor Ciphertext[i];
		iv[i]=plaintext[i];
	}

}

