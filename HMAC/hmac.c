#ifndef __HMAC_H__
#define __HMAC_H__
#include <stdint.h>

#define SHA1HashSize 20

enum
{
  shaSuccess = 0,
  shaNull,            /* Null pointer parameter */
  shaInputTooLong,    /* input data too long */
  shaStateError       /* called Input after Result */
};

#define FLAG_COMPUTED   1
#define FLAG_CORRUPTED  2

struct sha1
{
  uint8_t  Message_Block[64];       /* 512-bit message blocks         */
  uint32_t Intermediate_Hash[5];    /* Message Digest                 */
  uint32_t Length_Low;              /* Message length in bits         */
  uint32_t Length_High;             /* Message length in bits         */
  uint16_t Message_Block_Index;     /* Index into message block array */
  uint8_t  flags;
};

int sha1_reset (struct sha1* context);
int sha1_input (struct sha1* context, const uint8_t* message_array, unsigned length);
int sha1_result(struct sha1* context, uint8_t Message_Digest[SHA1HashSize]);

#define HMAC_SHA1_HASH_SIZE 20

void hmac_sha1(const uint8_t* key, const uint32_t keysize, const uint8_t* msg, const uint32_t msgsize, uint8_t* output);

#endif
/* __HMAC_H__ */


/* function doing the HMAC-SHA-1 calculation */
void hmac_sha1(const uint8_t* key, const uint32_t keysize, const uint8_t* msg, const uint32_t msgsize, uint8_t* output)
{
  struct sha1 outer, inner;
  uint8_t tmp;

  sha1_reset(&outer);
  sha1_reset(&inner);

  uint32_t i;
  for (i = 0; i < keysize; ++i)
  {
    tmp = key[i] ^ 0x5C;
    sha1_input(&outer, &tmp, 1);
    tmp = key[i] ^ 0x36;
    sha1_input(&inner, &tmp, 1);
  }
  for (; i < 64; ++i)
  {
    tmp = 0x5C;
    sha1_input(&outer, &tmp, 1);
    tmp = 0x36;
    sha1_input(&inner, &tmp, 1);
  }

  sha1_input(&inner, msg, msgsize);
  sha1_result(&inner, output);

  sha1_input(&outer, output, HMAC_SHA1_HASH_SIZE);
  sha1_result(&outer, output);
}

