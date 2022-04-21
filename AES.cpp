#include<stdio.h>
#include<string.h>

int Cipher_Round=0;	// 加密運算執行回合數
int block=0;	// 鑰匙的block數量
int mode; // 加解密方式
int count=0;// 做幾次加解密

unsigned char input[16];	// 加解密前字串 
unsigned char output[16];	// 加解密後字串 
unsigned char out_CO_8[16]; // CFB-8,OFB-8 加密後字串 
unsigned char temp[16];	
unsigned char IV[16]; // initialization vector
unsigned char process[4][4];	// 加密運算過程中的的矩陣 
unsigned char Roundkey[240];	// 儲存主要鑰匙跟擴充鑰匙的陣列 ( 128...176, 192...208, 256...240 )	
unsigned char key[32];	// 輸入的 Key

int S_Box[256] = {
	
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  
    
};

int S_Box_Inverse[256] = {
	
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
    
};

/* 
GF(2^8) 
KeyExpansion 會用到	
*/ 
int Rcon[11] = { 

	0x87, // 10000111
	0x01, // 00000001
	0x02, // 00000010
	0x04, // 00000100
	0x08, // 00001000
	0x10, // 00010000
	0x20, // 00100000
	0x40, // 01000000 ,256
	0x80, // 10000000 ,192
	0x1b, // 00011011  
	0x36  // 00110110 ,128
	
};

/* KeyExpansion */
void KeyExpansion() {
	
    unsigned char temp[4];
    unsigned char t;
    int count_Round_Key = 0; // 第幾個 round 
    
    // 第一回合 Key ( 128...0~15, 192...0~23, 256...0~31 )
    for (int i=0;i<block;i++) {
    	
        Roundkey[i*4] = key[i*4];
        Roundkey[i*4+1] = key[i*4+1];
        Roundkey[i*4+2] = key[i*4+2];
        Roundkey[i*4+3] = key[i*4+3];
        
    }

    // 產生其他回合鑰匙 ( 128...44 words, 192...52 words, 256...60 words )
    for (int i=block;i<(4*(Cipher_Round+1));i++) {
    	
    	// 前一個 word ( 4 bytes ) 
        for (int j=0;j<4;j++) temp[j] = Roundkey[(i-1)*4+j];
        
        if ((i%block)==0) {
        	
            // left shift
            t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // S-Box
            temp[0] = S_Box[(int)temp[0]];
            temp[1] = S_Box[(int)temp[1]];
            temp[2] = S_Box[(int)temp[2]];
            temp[3] = S_Box[(int)temp[3]];
            
            // 跟 [rcon 00 00 00] XOR ( XOR最左邊的byte )
            temp[0] ^= Rcon[i/block]; 
            
        }
        
        else if (block==8 && (i%block)==4) {
        	
            //only AES-256, S-Box
            temp[0] = S_Box[(int)temp[0]];
            temp[1] = S_Box[(int)temp[1]];
            temp[2] = S_Box[(int)temp[2]];
            temp[3] = S_Box[(int)temp[3]];
            
        }
        
        // 跟前 block*4 的 byte XOR ( ex: if 128... roundkey[16] = roundkey[0]^temp[0] ) 
        Roundkey[i*4+0] = Roundkey[count_Round_Key*4+0]^temp[0];
        Roundkey[i*4+1] = Roundkey[count_Round_Key*4+1]^temp[1];
        Roundkey[i*4+2] = Roundkey[count_Round_Key*4+2]^temp[2];
        Roundkey[i*4+3] = Roundkey[count_Round_Key*4+3]^temp[3]; 
        
        count_Round_Key++;
		 
    }
    
}

/* AddRoundKey */
void AddRoundKey(int round) {
    
	// 看round來使用key ( 一個 round = 16 bytes )
    for (int i=0;i<4;i++) {
    	
    	for (int j=0;j<4;j++) process[j][i] ^= Roundkey[(i*4+j)+(round*16)]; 	
    	
	}
            
}

/* S-Box */
void Sub_S_Box() {
	
    for (int i=0;i<4;i++) {
    	
    	for (int j=0;j<4;j++) process[i][j] = S_Box[process[i][j]];
    	
	}
        
}

/* S-Box Inverse */
void Sub_S_Box_Inv() {
	
    for (int i=0;i<4;i++) {
    	
    	for (int j=0;j<4;j++) process[i][j] = S_Box_Inverse[process[i][j]];
    	
	}
        
}

/* left Shift (row) */
void ShiftRows() {
	
    unsigned char temp;
    
    // 2nd row ( 左移 1 個 )
    temp    = process[1][0];
    process[1][0] = process[1][1];
    process[1][1] = process[1][2];
    process[1][2] = process[1][3];
    process[1][3] = temp;

    // 3th row ( 左移 2 個 ) 
    temp    = process[2][0];
    process[2][0] = process[2][2];
    process[2][2] = temp;
    temp    = process[2][1];
    process[2][1] = process[2][3];
    process[2][3] = temp;

    // 4th row ( 左移 3 個 ) 
    temp    = process[3][0];
    process[3][0] = process[3][3];
    process[3][3] = process[3][2];
    process[3][2] = process[3][1];
    process[3][1] = temp;
    
}

/* right Shift inverse (row) */
void ShiftRows_Inv() {
	
    unsigned char temp;
    
    // 2nd row ( 右移 1 個 ) 
    temp    = process[1][3];
    process[1][3] = process[1][2];
    process[1][2] = process[1][1];
    process[1][1] = process[1][0];
    process[1][0] = temp;

    // 3th row ( 右移 2 個 ) 
    temp    = process[2][0];
    process[2][0] = process[2][2];
    process[2][2] = temp;
    temp    = process[2][1];
    process[2][1] = process[2][3];
    process[2][3] = temp;

    // 4th row ( 右移 3 個 ) 
    temp    = process[3][0];
    process[3][0] = process[3][1];
    process[3][1] = process[3][2];
    process[3][2] = process[3][3];
    process[3][3] = temp;
    
}

/*
shift XOR 乘法 
(x << 1)  shift 1 bit
(x >> 7)  第8個bit
(x >> 7) & 0x01 檢查第8個bit是否為 1 
0x1b = 0001 1011 ( x^4 + x^3 + x + 1 )
*/
unsigned char SXOR(unsigned char x) {
	
	return ((x << 1) ^ (((x >> 7) & 0x01)*0x1b));
	
} 

/*  MixColumns */
void MixColumns() {
	
	unsigned char t0,t1,t2,t3;
	
	for (int i=0;i<4;i++) {
		
		t0 = process[0][i];
		t1 = process[1][i];
		t2 = process[2][i];
		t3 = process[3][i];
		
		// (02*process[0][i])^(03*process[1][i])^process[2][i]^process[3][i]
		process[0][i] = SXOR(t0)^(t1^SXOR(t1))^t2^t3;
		
		// process[0][i]^(02*process[1][i])^(03*process[2][i])^process[3][i]
		process[1][i] = t0^SXOR(t1)^(t2^SXOR(t2))^t3;
		
		// process[0][i]^process[1][i]^(02*process[2][i])^(03*process[3][i])
		process[2][i] = t0^t1^SXOR(t2)^(t3^SXOR(t3));
		
		// (03*process[0][i])^process[1][i]^process[2][i]^(02*process[3][i])
		process[3][i] = (t0^SXOR(t0))^t1^t2^SXOR(t3);
		
	}
    
}

/* InvMixColumns */
void MixColumns_Inv() {
	
	unsigned char t0,t1,t2,t3;
	unsigned char tt0,tt1,tt2,tt3;
	
	for (int i=0;i<4;i++) {
		
		t0 = process[0][i];
		t1 = process[1][i];
		t2 = process[2][i];
		t3 = process[3][i];
		
		// (0E*process[0][i])^(0B*process[1][i])^(0D*process[2][i])^(09*process[3][i])
		tt0 = SXOR(t0)^SXOR(SXOR(t0))^SXOR(SXOR(SXOR(t0)));
		tt1 = t1^SXOR(t1)^SXOR(SXOR(SXOR(t1)));
		tt2 = t2^SXOR(SXOR(t2))^SXOR(SXOR(SXOR(t2)));
		tt3 = t3^SXOR(SXOR(SXOR(t3)));
		process[0][i] = tt0^tt1^tt2^tt3;
		
		// (09*process[0][i])^(09*process[1][i])^(0B*process[2][i])^(0D*process[3][i])
		tt0 = t0^SXOR(SXOR(SXOR(t0)));
		tt1 = SXOR(t1)^SXOR(SXOR(t1))^SXOR(SXOR(SXOR(t1)));
		tt2 = t2^SXOR(t2)^SXOR(SXOR(SXOR(t2)));
		tt3 = t3^SXOR(SXOR(t3))^SXOR(SXOR(SXOR(t3)));
		process[1][i] = tt0^tt1^tt2^tt3;
		
		// (0D*process[0][i])^(09*process[1][i])^(0E*process[2][i])^(0B*process[3][i])
		tt0 = t0^SXOR(SXOR(t0))^SXOR(SXOR(SXOR(t0)));
		tt1 = t1^SXOR(SXOR(SXOR(t1)));
		tt2 = SXOR(t2)^SXOR(SXOR(t2))^SXOR(SXOR(SXOR(t2)));
		tt3 = t3^SXOR(t3)^SXOR(SXOR(SXOR(t3)));
		process[2][i] = tt0^tt1^tt2^tt3;
		
		// (0B*process[0][i])^(0D*process[1][i])^(09*process[2][i])^(0E*process[3][i])
		tt0 = t0^SXOR(t0)^SXOR(SXOR(SXOR(t0)));
		tt1 = t1^SXOR(SXOR(t1))^SXOR(SXOR(SXOR(t1)));
		tt2 = t2^SXOR(SXOR(SXOR(t2)));
		tt3 = SXOR(t3)^SXOR(SXOR(t3))^SXOR(SXOR(SXOR(t3)));
		process[3][i] = tt0^tt1^tt2^tt3;
		
	}
    
}

/* 加密 */
void Encryption() {
    
    // input 轉換成 column 型式 
    for (int i=0;i<4;i++) {
    	
    	for (int j=0;j<4;j++) {
        	
        	if(mode==0 || mode==1) process[j][i] = input[i*4+j];
        	else if (mode==3 || mode==5 || mode==6) process[j][i] = IV[i*4+j];
        	
		}
    	
	}
    
    AddRoundKey(0);
    
    //CBC
    if (mode==1) {
    	
   		for (int i=0;i<4;i++)  {
   			
   			for (int j=0;j<4;j++) {
   				
    			if (count==1) process[j][i] ^= IV[i*4+j];
    			else process[j][i] ^= output[i*4+j];
    			
			}
   			
		}
			
	}
	
    for (int round=1;round<Cipher_Round;round++) {
			
        Sub_S_Box();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
        
    }

    Sub_S_Box();
    ShiftRows();
    AddRoundKey(Cipher_Round);
	
    for(int i=0;i<4;i++)  {
    	
    	for(int j=0;j<4;j++) output[i*4+j]=process[j][i];
    	
	}
        
    
}

/* 解密 */
void Decryption() {
    
    // input 轉換成 column 型式 
    for (int i=0;i<4;i++) {
    	
    	for (int j=0;j<4;j++) {
        	
        	if(mode==0 || mode==1) process[j][i] = input[i*4+j];
        	
		}
    	
	}
    
    AddRoundKey(Cipher_Round);

    for (int round=Cipher_Round-1;round>0;round--) {
    	
        ShiftRows_Inv();
        Sub_S_Box_Inv();
        AddRoundKey(round);
        MixColumns_Inv();
        
    }

    ShiftRows_Inv();
    Sub_S_Box_Inv();
    AddRoundKey(0);

	//CBC
	if (mode==1) {
		
    	for (int i=0;i<4;i++)  {
    		
    		for (int j=0;j<4;j++) {
    			
    			if (count==1) process[j][i] ^= IV[i*4+j];
    			else process[j][i] ^= temp[i*4+j];
    			
			}
    		
		}
		
	}
	
    for(int i=0;i<4;i++)  {
    	
    	for(int j=0;j<4;j++) output[i*4+j]=process[j][i];
    	
	}
        
}

/* 檢查輸入 character 正確於否 */
int Input(unsigned char *inputArray, int num) {
	
	char check[num];
	char check_again;
	int dcheck=0;
				
	for (int cha=0;cha<num;cha++) {
		
		scanf("%c",&inputArray[cha]);
		check[cha] = inputArray[cha];
		
		// 檢查輸入的 character 是否為 enter 鍵 
		if (inputArray[cha]=='\n') return 0;
					
	}
	
	// 檢查有沒有超過 character 數量 
	while (true) {
		
		scanf("%c",&check_again);
		
		if (check_again=='\n') break;
		
		dcheck++;
		
	}
	
	if (dcheck==0) return 1;
	else return 0;
	
}

int main () {
	
	int EoD; // encryption or decryption 
	int check; // 檢查輸入的 character 是否正確 
	char enter; // 吃 enter 鍵 
	char c; // 抓看看 file 裡下一個是否有 character
	int Key_size=0;
	int flag=0; // 看 file 裡還有沒有 character 
	unsigned char input_key[32]; // 存 key 
	
	while (true) {
		
		printf("Encryption(1) or Decryption(0): ");
		scanf("%d",&EoD);
		
		if (EoD<0 || EoD>1) printf("\n 1 OR 0 \n\n");
		else break;
		
	}
	
	while (true) {
		
		printf("\n選擇模式\n( ECB: 0  CBC: 1  CFB-1: 2  CFB-8: 3  OFB-1: 4  OFB-8: 5  CTR: 6  ):");
		scanf("%d",&mode);
		scanf("%c",&enter);
	
		if ( (mode<0) || (mode>6) ) {
			
			printf("\n[ Please enter 0 ~ 6 ]\n\n");
			continue;
			
		}
		else if (mode!=0) {
		
			while (true) {
				
				printf("\n輸入 Initialization Vector ( 16 characters ):");
				
				check = Input(IV,16);
				
				if (check==0) {
					
					printf("\n[ 請輸入指定 character 數 ]\n\n");
					continue;
					
				}
				else break;
				
			}
		
		}
		
		break;
		
	}
	
	if (EoD==1) printf("\n~ AES Encryption ~\n");
	else printf("\n~ AES Decryption ~\n");
		
    while (true) {
    	
        printf("輸入 AES key size ( 128 , 192 , 256) : ");
        scanf("%d",&Key_size);
        scanf("%c",&enter);
        
        if (Key_size!=128 && Key_size!=192 && Key_size!=256) printf("\n[ Please enter 128 , 192 or 256 ]\n\n");
        else break;
        
  	}
				
	block=Key_size/32; // key block數量　( 128...4, 192...6, 256...8 ) 
    Cipher_Round=block+6; // 回和數 

    while (true) {
    	
    	if (Key_size==128) {
    
   			printf("\n輸入 AES KEY (16 characters) : ");
       		check = Input(key,16);
           	
   		}
    
   		else if (Key_size==192) {
   		
       		printf("\n輸入 AES KEY (24 characters) : ");
       		check = Input(key,24);
           	
   		}
    	
   		else if (Key_size==256) { 
   	
       		printf("\n輸入 AES KEY (32 characters) : ");
       		check = Input(key,32);
           	
   		}
    
    	if (check==1) break; 
    	else printf("\n[ 請輸入指定 character 數 ]\n\n");
    	
	}
	
    KeyExpansion();
    
    // 加密 
    if (EoD==1) {
    	
    	char file[30];
    	FILE *fp,*wp;
    	
    	while (true) {
    		
    		printf("\n輸入 plaintext file name => ");
    		scanf("%s", &file);
    	
    		// 找 file 
    		if ((fp=fopen(file,"rb"))==NULL) {
    		
        		printf("\n[ 找不到此檔案 ]\n");
        		continue;
        	
    		}
    		
    		break;
    		
		}

    	printf("\n輸入 Ciphertext file name => "); 
    	scanf("%s",&file); 
    	wp=fopen(file,"wb");
    	flag=1;
    	
    	while(flag==1) { 
    	
    		count++; //第幾次加密
        
        	for (int c=0;c<16;c++) {
        		
            	input[c] = fgetc(fp); // 從 file 抓一個 character 
				
				// 最後讀取時剩下的陣列內容設為 0 
            	if (feof(fp)) {
            		
                	for (int padding = c;padding<16;padding++) input[padding] = 0x00;
                	
                	flag = 0; // 表示 file 裡 character 以抓完 
            	}
            	
        	}
			
			// CFB-8 
			if (mode==3) {
				
				for (int i=0;i<16;i++) {
					
					Encryption();
					temp[0] = output[0];
					temp[0] ^= input[i];
					out_CO_8[i] = temp[0]; // 只保留最左邊  1 byte ( 8 bits ) 
					
					// 新 IV 
					for (int j=0;j<15;j++) IV[j] = IV[j+1];
					
					IV[15] = temp[0];
					
				}
				
			}
			// OFB-8 
			else if (mode==5) {
				
				for (int i=0;i<16;i++) {
					
					Encryption();
					temp[0] = output[0];
					
					// 新 IV 
					for (int j=0;j<15;j++) IV[j] = IV[j+1];
					
					IV[15] = temp[0];
					
					temp[0] ^= input[i];
					out_CO_8[i] = temp[0]; // 只保留最左邊  1 byte ( 8 bits )  
					
				}
				
			}
        	else Encryption(); 
        	
        	// CTR 
        	if (mode==6) {
        		
        		for (int i=15;i>=0;i--) {
        			
        			// 進位 
        			if (IV[i]==255) {
        				
        				IV[i] == 0;
						continue;	
						
					}
					
					IV[i]++; //counter + 1
					
				}
				
   				for (int i=0;i<16;i++) output[i] ^= input[i];
   				
			}
        	
    		// 密文輸出到檔案上
        	for(int c=0;c<16;c++)  {
        		
        		if (mode==3 || mode==5) fprintf(wp,"%c",out_CO_8[c]);
        		else fprintf(wp,"%c",output[c]);
        		
			}
        	
    		if ((c=fgetc(fp))==EOF) flag = 0;
    		else ungetc(c, fp);
    	
		}
		
		fclose(fp);
    	rewind(wp);
    	fclose(wp);
		
	}
	
	// 解密 
	else {
		
		char file[50];
		FILE *fp,*wp;
		
    	while (true) {
    		
    		printf("\n輸入 Ciphertext file name => ");
    		scanf("%s",&file);
    	
    		// 找 file 
    		if ((fp = fopen(file,"rb"))==NULL) {
    		
        		printf("\n[ 找不到此檔案 ]\n");
        		continue;
        	
    		}
    		
    		break;
    		
		}

    	printf("\n輸入 Plaintext file name  => "); 
    	scanf("%s", &file); 
    	wp = fopen(file,"wb");
    	flag = 1;
    	
    	while(flag==1) {
    		
    		count++; //第幾次解密
    		
    		if (mode==1) for (int i=0;i<16;i++) temp[i] = input[i];
       	
        	for (int c=0;c<16;c++) input[c] = fgetc(fp);
        	
        	// CFB-8 
        	if (mode==3) {
        		
				for (int i=0;i<16;i++) {
					
					Encryption();
					temp[0] = input[i];
					
					// 新 IV 
					for (int j=0;j<15;j++) IV[j] = IV[j+1];
					
					IV[15] = temp[0];
					
					temp[0] ^= output[0];
					out_CO_8[i] = temp[0]; // 只保留最左邊  1 byte ( 8 bits )  
					
				}
				
			}
			// OFB-8
			else if (mode==5) {
				
				for (int i=0;i<16;i++) {
					
					Encryption();
					temp[0] = output[0];
					
					// 新 IV 
					for (int j=0;j<15;j++) IV[j] = IV[j+1];
					
					IV[15] = temp[0];
					
					temp[0] ^= input[i];
					out_CO_8[i] = temp[0]; // 只保留最左邊  1 byte ( 8 bits )  
					
				}
				
			}
			// CTR 
			else if (mode==6) {
				
				Encryption();
				
        		for (int i=15;i>=0;i--) {
        			
        			// 進位 
        			if (IV[i]==255) {
        				
        				IV[i] == 0;
						continue;
							
					}
					
					IV[i]++; //counter + 1
					
				}
				
   				for (int i=0;i<16;i++) output[i] ^= input[i];
   				
			}
        	else Decryption(); 
        	
        	for (int c=0;c<16;c++) {
        		
            	// 處理後面空白字 
            	if (output[c]==0x00 && (mode==0 || mode==1) ) {
            		
                	flag = 0;
                	break;
                	
            	}
            	else if (out_CO_8[c]==0x00 && (mode==3 || mode==5) ) {
            		
            		flag = 0;
                	break;
                	
				}
            
            	if (mode==3 || mode==5) fprintf(wp,"%c",out_CO_8[c]);
            	else fprintf(wp,"%c",output[c]);
            	
        	}
        	
    		if ((c = fgetc(fp)) == EOF) flag = 0;
    		else ungetc(c, fp);
    		
		}
		
		fclose(fp);
    	rewind(wp);
    	fclose(wp);
	
	}
    
    if (EoD == 1) printf("\nEncryption process success !! \n");
    else printf("\nDecryption process success !! \n");
    
    return 0;
	
}
