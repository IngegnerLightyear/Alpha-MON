//#ifndef _RIJNDAEL_H_
#define _RIJNDAEL_H_
#define _RIJNDAEL_CPP_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

/* We assume that unsigned int is 32 bits long....  */
typedef unsigned char  UINT8;
typedef unsigned int   UINT32;
typedef unsigned short UINT16;

/* Error codes */
#define RIJNDAEL_SUCCESS 0
#define RIJNDAEL_UNSUPPORTED_MODE -1
#define RIJNDAEL_UNSUPPORTED_DIRECTION -2
#define RIJNDAEL_UNSUPPORTED_KEY_LENGTH -3
#define RIJNDAEL_BAD_KEY -4
#define RIJNDAEL_NOT_INITIALIZED -5
#define RIJNDAEL_BAD_DIRECTION -6
#define RIJNDAEL_CORRUPTED_DATA -7

typedef enum Mode_e Mode;
typedef enum Direction_e Direction;
typedef enum KeyLength_e KeyLength;
typedef enum State_e State;

//enum Direction_e { Encrypt , Decrypt };
//enum Mode_e { ECB , CBC , CFB1 };
//enum KeyLength_e { Key16Bytes , Key24Bytes , Key32Bytes };
//enum State_e { Valid , Invalid };

//typedef struct rijndael rijndael;

typedef struct rijndael
{
	enum Direction_e { Encrypt , Decrypt };
        enum Mode_e { ECB , CBC , CFB1 };
        enum KeyLength_e { Key16Bytes , Key24Bytes , Key32Bytes };
        enum State_e { Valid , Invalid };

	State     m_state;
	Mode      m_mode;
	Direction m_direction;
	UINT8     m_initVector[MAX_IV_SIZE];
	UINT32    m_uRounds;
	UINT8     m_expandedKey[_MAX_ROUNDS+1][4][4];

	UINT8 S[256], l;

	UINT8 T1[256][4];
	UINT8 T2[256][4];
	UINT8 T3[256][4];
	UINT8 T4[256][4];
	UINT8 T5[256][4];
	UINT8 T6[256][4];
	UINT8 T7[256][4];
	UINT8 T8[256][4];

	UINT8 S5[256];

	UINT8 U1[256][4];
	UINT8 U2[256][4];
	UINT8 U3[256][4];
	UINT8 U4[256][4];

	UINT32 rcon[30];

	/* Functions */
        //int (*rijndael_init)(rijndael * self, Mode mode, Direction dir, const UINT8 *key, KeyLength keyLen, UINT8 * initVector);
        //int (*blockEncrypt)(rijndael * self, const UINT8 *input, int inputLen, UINT8 *outBuffer);
        //int (*padEncrypt)(rijndael * self, const UINT8 *input, int inputOctets, UINT8 *outBuffer);

        //void (*keySched)(rijndael * self, UINT8 key[_MAX_KEY_COLUMNS][4]);
        //void (*keyEncToDec)(rijndael * self);
        //void (*r_encrypt)(rijndael * self, const UINT8 a[16], UINT8 b[16]);
        //void (*r_decrypt)(rijndael * self, const UINT8 a[16], UINT8 b[16]);
} rijndael;

void init_rijndael_OP(rijndael * self);
int rijndael_init(rijndael * self, Mode mode,Direction dir,const UINT8 * key,KeyLength keyLen,UINT8 * initVector);
int blockEncrypt(rijndael * self, const UINT8 *input,int inputLen,UINT8 *outBuffer);
int padEncrypt(rijndael * self, const UINT8 *input, int inputOctets, UINT8 *outBuffer);
int blockDecrypt(rijndael * self, const UINT8 *input, int inputLen, UINT8 *outBuffer);
int padDecrypt(rijndael * self, const UINT8 *input, int inputOctets, UINT8 *outBuffer);
void keySched(rijndael * self, UINT8 key[_MAX_KEY_COLUMNS][4]);
void keyEncToDec(rijndael * self);
static inline UINT32 encrypt_b_from_T(rijndael * self, UINT8 ind1, UINT8 ind2, UINT8 ind3, UINT8 ind4);
static inline UINT32 decrypt_b_from_T(rijndael * self, UINT8 ind1, UINT8 ind2, UINT8 ind3, UINT8 ind4);
void r_encrypt(rijndael * self, const UINT8 a[16], UINT8 b[16]);
void r_decrypt(rijndael * self, const UINT8 a[16], UINT8 b[16]);
