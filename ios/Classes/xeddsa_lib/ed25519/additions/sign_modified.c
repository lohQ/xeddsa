#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "../ge.h"
#include "../sc.h"
#include "zeroize.h"
#include "crypto_additions.h"

/* NEW: Compare to pristine crypto_sign() 
   Uses explicit private key for nonce derivation and as scalar,
   instead of deriving both from a master key.
*/
int crypto_sign_modified(
  unsigned char *sm,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, const unsigned char* pk,
  const unsigned char* random
)
{
  unsigned char nonce[64];
  unsigned char hram[64];
  ge_p3 R;
  int count=0;

  /* NEW : add prefix to separate hash uses - see .h */
  sm[0] = 0xFE;
  // some little changes
  memset(sm + 1,0xFF,31);
  // for (count = 1; count < 32; count++){
  //   sm[count] = 0xFF;
  // }

  memmove(sm + 32,sk,32); /* NEW: Use privkey directly for nonce derivation */
  memmove(sm + 64,m,mlen);

  /* NEW: add suffix of random data */
  /* NEWER: not using random data as it causes the app to crash */
  memmove(sm + mlen + 64, sk, 32);
  // in this app we only signs public key so mlen = 32
  memmove(sm + mlen + 96, m, mlen); 
  // memmove(sm + mlen + 64, random, 64);

  crypto_hash_sha512(nonce,sm,mlen + 128);
  memmove(sm + 32,pk,32);

  sc_reduce(nonce);

  ge_scalarmult_base(&R,nonce);
  ge_p3_tobytes(sm,&R);

  crypto_hash_sha512(hram,sm,mlen + 64);
  sc_reduce(hram);
  sc_muladd(sm + 32,hram,sk,nonce); /* NEW: Use privkey directly */

  /* Erase any traces of private scalar or
     nonce left in the stack from sc_muladd */
  zeroize_stack();
  zeroize(nonce, 64);
  return 0;
}
