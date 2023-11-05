//Implementation of the AES algorithm(ECB, CBC, CTR mode).
// We can choose Block size in aes.h

#include <string.h> 
#include <stdint.h>
#include <stddef.h>

#ifndef _AES_H_
#define _AES_H_

#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif


#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AESInitCtx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AESInitCtx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AESCtxSet_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)

void AES_ECB_Encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_Decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)

void AES_CBC_Encrypt_Buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_Decrypt_Buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

void AES_CTR_Xcrypt_Buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)


#endif // _AES_H_


#define C 4 // number of columns

#if defined(AES256) && (AES256 == 1)
    #define Nkey 8
    #define NRounds 14
#elif defined(AES192) && (AES192 == 1)
    #define Nkey 6
    #define NRounds 12
#else
    #define Nkey 4   
    #define NRounds 10  // The number of rounds
#endif

typedef uint8_t state_t[4][4];


static const uint8_t SBox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
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
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t RSbox[256] = {
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
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define SBoxValue(num1) (SBox[(num1)])

static void KeyExp(uint8_t* roundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t temp[4]; 
  
  
  for (i = 0; i < Nkey; ++i)
  {
    roundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    roundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    roundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    roundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  for (i = Nkey; i < C * (NRounds + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      temp[1]=roundKey[k + 1];
      temp[0]=roundKey[k + 0];
      temp[2]=roundKey[k + 2];
      temp[3]=roundKey[k + 3];
    }

    if (i % Nkey == 0)
    {
      {
        const uint8_t u8tmp = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = u8tmp;
      }

      {
        temp[0] = SBoxValue(temp[0]);
        temp[1] = SBoxValue(temp[1]);
        temp[2] = SBoxValue(temp[2]);
        temp[3] = SBoxValue(temp[3]);
      }

      temp[0] = temp[0] ^ Rcon[i/Nkey];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      {
        temp[0] = SBoxValue(temp[0]);
        temp[1] = SBoxValue(temp[1]);
        temp[2] = SBoxValue(temp[2]);
        temp[3] = SBoxValue(temp[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nkey) * 4;
    roundKey[j + 0] = roundKey[k + 0] ^ temp[0];
    roundKey[j + 1] = roundKey[k + 1] ^ temp[1];
    roundKey[j + 2] = roundKey[k + 2] ^ temp[2];
    roundKey[j + 3] = roundKey[k + 3] ^ temp[3];
  }
}

void AESInitCtx(struct AES_ctx* _ctx, const uint8_t* _key)
{
  KeyExp(_ctx->RoundKey, _key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AESInitCtx_iv(struct AES_ctx* _ctx, const uint8_t* _key, const uint8_t* iv)
{
  KeyExp(_ctx->RoundKey, _key);
  memcpy (_ctx->Iv, iv, AES_BLOCKLEN);
}
void AESCtxSet_iv(struct AES_ctx* _ctx, const uint8_t* iv)
{
  memcpy (_ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

static void AddRKey(uint8_t _round, state_t* _state, const uint8_t* _RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*_state)[i][j] ^= _RoundKey[(_round * C * 4) + (i * C) + j];
    }
  }
}

static void SUBBytes(state_t* _state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*_state)[j][i] = SBoxValue((*_state)[j][i]);
    }
  }
}

static void ShiftRows(state_t* _state)
{
  uint8_t _temp;
 
  _temp           = (*_state)[0][1];
  (*_state)[0][1] = (*_state)[1][1];
  (*_state)[1][1] = (*_state)[2][1];
  (*_state)[2][1] = (*_state)[3][1];
  (*_state)[3][1] = _temp;
  
  _temp           = (*_state)[0][2];
  (*_state)[0][2] = (*_state)[2][2];
  (*_state)[2][2] = _temp;

  _temp           = (*_state)[1][2];
  (*_state)[1][2] = (*_state)[3][2];
  (*_state)[3][2] = _temp;

  _temp           = (*_state)[0][3];
  (*_state)[0][3] = (*_state)[3][3];
  (*_state)[3][3] = (*_state)[2][3];
  (*_state)[2][3] = (*_state)[1][3];
  (*_state)[1][3] = _temp;
}

static uint8_t XTime(uint8_t _x)
{
  return ((_x<<1) ^ (((_x>>7) & 1) * 0x1b));
}

static void MIXColumns(state_t* _state)
{
  uint8_t i;
  uint8_t _Tmp, _Tm, _t;
  for (i = 0; i < 4; ++i)
  {  
    _t   = (*_state)[i][0];
    _Tmp = (*_state)[i][0] ^ (*_state)[i][1] ^ (*_state)[i][2] ^ (*_state)[i][3] ;
    _Tm  = (*_state)[i][0] ^ (*_state)[i][1] ; _Tm = XTime(_Tm);  (*_state)[i][0] ^= _Tm ^ _Tmp ;
    _Tm  = (*_state)[i][1] ^ (*_state)[i][2] ; _Tm = XTime(_Tm);  (*_state)[i][1] ^= _Tm ^ _Tmp ;
    _Tm  = (*_state)[i][2] ^ (*_state)[i][3] ; _Tm = XTime(_Tm);  (*_state)[i][2] ^= _Tm ^ _Tmp ;
    _Tm  = (*_state)[i][3] ^ _t ;              _Tm = XTime(_Tm);  (*_state)[i][3] ^= _Tm ^ _Tmp ;
  }
}

#ifndef MultiplyAsAFunction
  #define MultiplyAsAFunction 0
#endif


#if MultiplyAsAFunction
static uint8_t Mul(uint8_t _x, uint8_t _y)
{
  return (((_y & 1) * _x) ^
       ((_y>>1 & 1) * XTime(_x)) ^
       ((_y>>2 & 1) * XTime(XTime(_x))) ^
       ((_y>>3 & 1) * XTime(XTime(XTime(_x)))) ^
       ((_y>>4 & 1) * XTime(XTime(XTime(XTime(_x)))))); 
  }
#else
#define Mul(x, y)                                       \
      (((y & 1) * x) ^                                \
       ((y>>1 & 1) * XTime(x)) ^                      \
       ((y>>2 & 1) * XTime(XTime(x))) ^               \
       ((y>>3 & 1) * XTime(XTime(XTime(x)))) ^        \
       ((y>>4 & 1) * XTime(XTime(XTime(XTime(x)))))) \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

#define SBoxInvert(num2) (RSbox[(num2)])

static void Inv_Mix_Columns(state_t* _state)
{
  int i;
  uint8_t a1, b1, c1, d1;
  for (i = 0; i < 4; ++i)
  { 
    a1 = (*_state)[i][0];
    b1 = (*_state)[i][1];
    c1 = (*_state)[i][2];
    d1 = (*_state)[i][3];

    (*_state)[i][0] = Mul(a1, 0x0e) ^ Mul(b1, 0x0b) ^ Mul(c1, 0x0d) ^ Mul(d1, 0x09);
    (*_state)[i][1] = Mul(a1, 0x09) ^ Mul(b1, 0x0e) ^ Mul(c1, 0x0b) ^ Mul(d1, 0x0d);
    (*_state)[i][2] = Mul(a1, 0x0d) ^ Mul(b1, 0x09) ^ Mul(c1, 0x0e) ^ Mul(d1, 0x0b);
    (*_state)[i][3] = Mul(a1, 0x0b) ^ Mul(b1, 0x0d) ^ Mul(c1, 0x09) ^ Mul(d1, 0x0e);
  }
}

static void Inv_Sub_Bytes(state_t* _state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*_state)[j][i] = SBoxInvert((*_state)[j][i]);
    }
  }
}

static void Inv_Shift_Rows(state_t* _state)
{
  uint8_t temp1;
 
  temp1 = (*_state)[3][1];
  (*_state)[3][1] = (*_state)[2][1];
  (*_state)[2][1] = (*_state)[1][1];
  (*_state)[1][1] = (*_state)[0][1];
  (*_state)[0][1] = temp1;

  temp1 = (*_state)[0][2];
  (*_state)[0][2] = (*_state)[2][2];
  (*_state)[2][2] = temp1;

  temp1 = (*_state)[1][2];
  (*_state)[1][2] = (*_state)[3][2];
  (*_state)[3][2] = temp1;

 
  temp1 = (*_state)[0][3];
  (*_state)[0][3] = (*_state)[1][3];
  (*_state)[1][3] = (*_state)[2][3];
  (*_state)[2][3] = (*_state)[3][3];
  (*_state)[3][3] = temp1;
}
#endif


static void CipherText(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  AddRKey(0, state, RoundKey);

  for (round = 1; ; ++round)
  {
    SUBBytes(state);
    ShiftRows(state);
    if (round == NRounds) {
      break;
    }
    MIXColumns(state);
    AddRKey(round, state, RoundKey);
  }

  AddRKey(NRounds, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void Inv_CipherText(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  AddRKey(NRounds, state, RoundKey);

  for (round = (NRounds - 1); ; --round)
  {
    Inv_Shift_Rows(state);
    Inv_Sub_Bytes(state);
    AddRKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    Inv_Mix_Columns(state);
  }

}
#endif

#if defined(ECB) && (ECB == 1)
void AES_ECB_Encrypt(const struct AES_ctx* _ctx, uint8_t* buf)
{
 
  CipherText((state_t*)buf, _ctx->RoundKey);
}

void AES_ECB_Decrypt(const struct AES_ctx* _ctx, uint8_t* buf)
{
    Inv_CipherText((state_t*)buf, _ctx->RoundKey);
}

#endif 

#if defined(CBC) && (CBC == 1)
static void XOR_With_Iv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) 
  {
    buf[i] ^= Iv[i];
  }
}
void AES_CBC_Encrypt_Buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XOR_With_Iv(buf, Iv);
    CipherText((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }

  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_Decrypt_Buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t store_Next_Iv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(store_Next_Iv, buf, AES_BLOCKLEN);
    Inv_CipherText((state_t*)buf, ctx->RoundKey);
    XOR_With_Iv(buf, ctx->Iv);
    memcpy(ctx->Iv, store_Next_Iv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}
#endif


#if defined(CTR) && (CTR == 1)
void AES_CTR_Xcrypt_Buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) 
    {
      
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      CipherText((state_t*)buffer,ctx->RoundKey);

      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}
#endif