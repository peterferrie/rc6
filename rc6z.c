/**
  Copyright © 2015 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include "rc6.h"

void rc6_crypt (void *key, void *data)
{
    w128_t  *x;
    uint32_t A, B, C, D, T0, T1, i;
    uint32_t S[RC6_KR], L[8];
    uint32_t *k;
    
    x =(w128_t*)data;
    k =(uint32_t*)S;
    
    // initialize L with 256-bit key
    memcpy(&L, key, 32);

    // initialize S with constants
    for (A=RC6_P, i=0; i<RC6_KR; i++) {
      S[i] = A;
      A += RC6_Q;
    }
    
    // mix with key
    for (A=0,B=0,i=0; i<RC6_KR*3; i++) {
      A = S[i%RC6_KR] = ROTL32(S[i%RC6_KR] + A+B, 3);  
      B = L[i&7] = ROTL32(L[i&7] + A+B, A+B);
    }
    
    // load plaintext
    A=x->w[0]; B=x->w[1];
    C=x->w[2]; D=x->w[3];
    
    B += *k; k++; D += *k; k++;
    
    for (i=0; i<RC6_ROUNDS; i++) {
      T0 = ROTL32(B * (2 * B + 1), 5);
      T1 = ROTL32(D * (2 * D + 1), 5);
      
      A = ROTL32(A ^ T0, T1) + *k; k++;
      C = ROTL32(C ^ T1, T0) + *k; k++;
      // rotate 32-bits to the left
      T0 = A;
      A  = B; B  = C;
      C  = D; D  = T0;
    }
    
    A += *k; k++; C += *k; k++;

    // save ciphertext
    x->w[0]=A; x->w[1]=B;
    x->w[2]=C; x->w[3]=D;
}
