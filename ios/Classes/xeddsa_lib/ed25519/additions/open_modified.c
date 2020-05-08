#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "../nacl_includes/crypto_verify_32.h"
#include "../ge.h"
#include "../sc.h"
#include "crypto_additions.h"

int crypto_sign_open_modified(
  unsigned char *m,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
)
{
  unsigned char pkcopy[32];
  unsigned char rcopy[32];
  unsigned char scopy[32];
  unsigned char h[64];
  unsigned char rcheck[32];
  ge_p3 A;
  ge_p2 R;

  // if (smlen < 64) goto badsig;
  // if (sm[63] & 224) goto badsig; /* strict parsing of s */
  // if (ge_frombytes_negate_vartime(&A,pk) != 0) goto badsig;
  if (smlen < 64) return -3;
  if (sm[63] & 224) return -4; /* strict parsing of s */
  if (ge_frombytes_negate_vartime(&A,pk) != 0) return -5;

  memmove(pkcopy,pk,32);
  memmove(rcopy,sm,32);
  memmove(scopy,sm + 32,32);

  memmove(m,sm,smlen);
  memmove(m + 32,pkcopy,32);
  crypto_hash_sha512(h,m,smlen);
  sc_reduce(h);

  ge_double_scalarmult_vartime(&R,h,&A,scopy);
  ge_tobytes(rcheck,&R);

  int result = crypto_verify_32(rcheck,rcopy);
  if (result == 0) {
    return 0;
  }else{
    return -6;
  }

// badsig:
//   return -3;
}
