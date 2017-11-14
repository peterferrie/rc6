;
;  Copyright © 2015, 2017 Odzhan, Peter Ferrie. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; -----------------------------------------------
; RC6 block cipher in x86 assembly (encryption only)
;
; https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf
;
; size: 160 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------

bits 32

%define RC6_ROUNDS 20
%define RC6_KR     (2*(RC6_ROUNDS+2))
%define RC6_P      0xB7E15163
%define RC6_Q      0x9E3779B9

%define A esi
%define B ebx
%define C edx
%define D ebp

%define S edi
%define L esp

rc6_crypt:
    pushad
    mov    esi, [esp+32+4] ; key
    mov    ebx, [esp+32+8] ; data    
    xor    ecx, ecx
    mul    ecx
    mov    ch, 1
    sub    esp, ecx      ; allocate 256 bytes
    ; initialize L with 256-bit key    
    mov    edi, esp    
    shr    ecx, 2        ; 256/4 = 32
    rep    movsb
    ; initialize S   
    pushad
    mov    eax, RC6_P
    mov    cl, RC6_KR    
r_l0:
    stosd
    add    eax, RC6_Q
    loop   r_l0
    popad
    ; create subkeys
    xor    A, A
    xor    B, B    
r_l1:
    ; A = S[i%RC6_KR] = ROTL32(S[i%RC6_KR] + A+B, 3); 
    push   RC6_KR
    pop    ecx
    mov    eax, ebx
    cdq
    idiv   eax, ecx
    lea    A, [A+B]
    add    A, [S+edx*4]
    rol    A, 3
    mov    [S+edx*4], A
    ; B = L[i&7] = ROTL32(L[i&7] + A+B, A+B);
    mov    edx, ecx
    and    dl, 7
    add    B, A
    mov    ecx, B
    add    B, [L+edx*4]
    rol    B, cl
    mov    [L+edx*4], B
    inc    ebx
    cmp    bl, RC6_KR*3
    jnz    r_l1     
    ; load plaintext
    push   esi
    lodsd
    xchg   eax, D
    lodsd
    xchg   eax, B
    lodsd
    xchg   eax, C
    lodsd
    xchg   eax, D
    xchg   eax, A    
    push   RC6_ROUNDS
    pop    ecx    
    ; B += *k; k++;
    add    B, [edi]
    scasd
    ; D += *k; k++;
    add    D, [edi]
    scasd
r6c_l3:
    push   ecx    
    ; T0 = ROTL32(B * (2 * B + 1), 5);
    lea    eax, [B+B+1]
    imul   eax, B
    rol    eax, 5
    ; T1 = ROTL32(D * (2 * D + 1), 5);
    lea    ecx, [D+D+1]
    imul   ecx, D
    rol    ecx, 5
    ; A = ROTL32(A ^ T0, T1) + *k; k++;
    xor    A, eax
    rol    A, cl
    add    A, [edi]
    scasd
    ; C = ROTL32(C ^ T1, T0) + *k; k++;
    xor    C, ecx
    xchg   eax, ecx
    rol    C, cl
    add    C, [edi]
    scasd
    ; swap
    xchg   D, eax
    xchg   C, eax
    xchg   B, eax
    xchg   A, eax
    xchg   D, eax
    ; decrease counter
    pop    ecx
    loop   r6c_l3
    ; A += *k; k++;
    add    A, [edi]
    ; C += *k; k++;
    add    C, [edi+4]
    ; save ciphertext
    pop    edi    
    xchg   eax, A
    stosd
    xchg   eax, B
    stosd
    xchg   eax, C
    stosd
    xchg   eax, D
    stosd    
    lea    esp, [esp+4*ecx]
    popad
    ret
    