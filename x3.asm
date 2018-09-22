SECTION .data

hello:     db 'AES-128-CBC with AES-NI demo by Losi',10,13,13
helloLen:  equ $-hello
initv:     db 'Random IV a CBC-hez:',10,13
initvlen:  equ $-initv
cleartxt:     db 'Plaintext, block1-7:',10,13
cleartxtlen:  equ $-cleartxt
ciphertext:   db 'Ciphertext block1-7:',10,13,13
ciphertextlen:  equ $-ciphertext
secretkey:     db 'Secret Key:',10,13,13
secretkeylen:  equ $-secretkey


block1     : db 41h,45h,53h,20h,32h,35h,36h,20h,61h,73h,73h,65h,6dh,62h,6ch,79h
block2     : db 20h,74h,65h,73h,74h,2eh,20h,4dh,75h,73h,74h,20h,77h,72h,69h,74h
block3     : db 65h,20h,73h,6fh,6dh,65h,20h,73h,74h,75h,66h,66h,20h,68h,65h,72h
block4     : db 65h,20h,74h,6fh,20h,67h,65h,74h,20h,6dh,6fh,72h,65h,20h,74h,68h
block5     : db 61h,6eh,20h,6fh,6eh,65h,20h,62h,6ch,6fh,63h,6bh,20h,69h,6eh,20h
block6     : db 6fh,72h,64h,65h,72h,20h,74h,6fh,20h,73h,68h,6fh,77h,20h,43h,42h
block7     : db 43h,20h,6dh,6fh,64h,65h,2eh,00h,00h,00h,00h,00h,00h,00h,00h,00h
key        : db 0fh,0eh,0dh,0ch,0bh,0ah,09h,08h,07h,06h,05h,04h,03h,02h,01h,00h
init       : db 43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h,43h

hexadec    : db '0123456789abcdefgh'
file       : db	'/dev/urandom'
heap_base  : dd 0                                ; Memory address for base of our heap

SECTION .text
global _start
_start:
                                                 ; *** string kiiratas linux system call-al ***
mov     eax,4                                    ; 'write' system call = 4
mov     ebx,1                                    ; file descriptor 1 = STDOUT
mov     ecx,hello                                ; string to write
mov     edx,helloLen                             ; length of string to write
int     80h                                      ; call the kernel

                                                 ; Use `brk` syscall to get     current memory address
                                                 ; For the bottom of our heap This can be achieved
                                                 ; by calling brk with an address (EBX) of 0
                                                 ; *** memoria lefoglalasa ***
mov eax, 45                                      ; brk system call
xor ebx, ebx                                     ; don't request additional space, we just want to 
                                                 ; get the memory address for the base of our processes heap area.
int 0x80
mov [heap_base], eax                             ; Save the heap base

                                                 ; Now allocate some space (8192 bytes)
mov     eax, 45                                  ; brk system call
mov     ebx, [heap_base]                         ; ebx = address for base of heap
add     ebx, 0x2000                              ; increase heap by 8192 bytes
int     0x80

                                                 ; *** olvsunk egy filebol, meghozz a /dev/urandomból 16 byteot ***
mov     eax, 5                                   ; sys_open
mov     ebx, file                                ; file
mov     ecx, 0                                   ; Read/Write permissions read only
int     80h

    
mov     ebx,  eax                                ;   file_descriptor,
mov     eax,  3                                  ;
mov     ecx,  [heap_base]                        ;   *buf,
mov     edx,  16                                 ;   *bufsize
int     80h                                      ;


mov     eax,6
int     80h


mov     r15d,ecx                                 ; *** kiirjuk hogy mi lesz a random IV erteke
mov     eax,4                                    ; 'write' system call = 4
mov     ebx,1                                    ; file descriptor 1 = STDOUT
mov     ecx,initv                                ; string to write
mov     edx,initvlen                             ; length of string to write
int     80h                                      ; call the kernel
mov     ecx,r15d

movdqa  xmm5,[ecx]
movdqa  xmm4,xmm5
call    nyomtatxmm5                               
                                                 ; *** kiirjuk a titkos kulcsot a kepernyore
mov     eax,4                                    ; 'write' system call = 4
mov     ebx,1                                    ; file descriptor 1 = STDOUT
mov     ecx,secretkey                            ; string to write
mov     edx,secretkeylen                         ; length of string to write
int     80h                                      ; call the kernel



movdqu  xmm5,[key]                               ; print key
call    nyomtatxmm5

mov     eax,4                                    ; 'write' system call = 4
mov     ebx,1                                    ; file descriptor 1 = STDOUT
mov     ecx,cleartxt                             ; string to write
mov     edx,cleartxtlen                          ; length of string to write
int     80h                                      ; call the kernel



xor     ebx,ebx                                  ; print block1-block7 cleartext
mov     bx,16    
mov     ax,6
megkell2:
push    ax
push    bx
movdqu  xmm5,[block1+ebx]
call    nyomtatxmm5
pop     bx
pop     ax
add     bx,16
dec     ax
jnz     megkell2

mov     ecx, [heap_base]
add     ecx, 500                                 ; ebx = heap+500 ide nyugodtan irhatunk


movdqu  xmm1, [key]
movdqu  [ecx], xmm1                              ; elso helyre megy a kulcs siman,ez meg jo
add     ecx,16                                   ; ide jojjon a kovetkezo +16

                                                 ; *** AES128 10 db round key generalasa a titkos kulcsbol
aeskeygenassist xmm2, xmm1, 0x1
call            key_expansion_128
movdqu          xmm15,xmm1

aeskeygenassist xmm2, xmm1, 0x2
call            key_expansion_128
movdqu          xmm14,xmm1

aeskeygenassist xmm2, xmm1, 0x4
call            key_expansion_128
movdqu          xmm13,xmm1

aeskeygenassist xmm2, xmm1, 0x8
call            key_expansion_128
movdqu          xmm12,xmm1

aeskeygenassist xmm2, xmm1, 0x10
call            key_expansion_128
movdqu          xmm11,xmm1

aeskeygenassist xmm2, xmm1, 0x20
call            key_expansion_128
movdqu          xmm10,xmm1

aeskeygenassist xmm2, xmm1, 0x40
call            key_expansion_128
movdqu          xmm9,xmm1

aeskeygenassist xmm2, xmm1, 0x80
call            key_expansion_128
movdqu          xmm8,xmm1

aeskeygenassist xmm2, xmm1, 0x1b
call            key_expansion_128
movdqu          xmm7,xmm1

aeskeygenassist xmm2, xmm1, 0x36
call            key_expansion_128
movdqu          xmm6,xmm1

jmp     END;
key_expansion_128:
pshufd  xmm2, xmm2, 0xff
vpslldq xmm3, xmm1, 0x4
pxor    xmm1, xmm3
vpslldq xmm3, xmm1, 0x4
pxor    xmm1, xmm3
vpslldq xmm3, xmm1, 0x4
pxor    xmm1, xmm3
pxor    xmm1, xmm2
ret
END:


mov     eax,4                                    ; 'write' system call = 4
mov     ebx,1                                    ; file descriptor 1 = STDOUT
mov     ecx,ciphertext                           ; string to write
mov     edx,ciphertextlen                        ; length of string to write
int     80h                                      ; call the kernel



mov     ebx, [heap_base]
mov     ecx, 500
add     ebx,ecx      ;ebx=heap+100



movdqu  xmm5,[block1]                            ; *** kezdodik a titkositas maga, elso blokkot meg
;movdqu xmm4,[init]                              ; debug with fixed IV

movdqu  xmm0,[ebx]
pxor    xmm5, xmm4                               ; CBC -> ezert az elso blokkot xoroljuk az IV-vel
pxor    xmm5, xmm0                               ; Whitening step (Round 0) 
aesenc  xmm5, xmm15                              ; Round 1  
aesenc  xmm5, xmm14                              ; Round 2
aesenc  xmm5, xmm13                              ; Round 3
aesenc  xmm5, xmm12                              ; Round 4
aesenc  xmm5, xmm11                              ; Round 5
aesenc  xmm5, xmm10                              ; Round 6
aesenc  xmm5, xmm9                               ; Round 7
aesenc  xmm5, xmm8                               ; Round 8
aesenc  xmm5, xmm7                               ; Round 9
aesenclast xmm5, xmm6                            ; Round 10


call    nyomtatxmm5

xor     ebx,ebx
mov     bx,16
mov     ax,6

megkell:                                         ;a tobbi blokk mehet cikluba
push    ax
push    bx
movdqa  xmm1,xmm5
movdqu  xmm5,[block1+ebx]
pxor    xmm5,xmm1                                ;itt mar az elozo titkositott ertekkel xorolunk

pxor    xmm5, xmm0                               ; Whitening step (Round 0)
aesenc  xmm5, xmm15                              ; Round 1
aesenc  xmm5, xmm14                              ; Round 2
aesenc  xmm5, xmm13                              ; Round 3
aesenc  xmm5, xmm12                              ; Round 4
aesenc  xmm5, xmm11                              ; Round 5
aesenc  xmm5, xmm10                              ; Round 6
aesenc  xmm5, xmm9                               ; Round 7
aesenc  xmm5, xmm8                               ; Round 8
aesenc  xmm5, xmm7                               ; Round 9
aesenclast xmm5, xmm6                            ; Round 10

call    nyomtatxmm5 
pop     bx
pop     ax
add     bx,16
dec     ax
jnz     megkell                                  ;1+6 blokk

jmp     vege




nyomtatxmm5:                                     ; *** szubrutin egy XMM regiszter kepernyore valo kiiratasahoz   
    mov     eax, [heap_base]                     ; Get pointer to the heap's base
    movdqu  [eax], xmm5                          ; mov value 25 to DWORD at heapbase+0xFFF
    mov     byte [eax+16],10

    xor     ebx,ebx
    xor     edx,edx
    xor     ecx,ecx
    mov     esi, [heap_base]
    mov     ebp, hexadec                         ;*** HEXA konvertalo tablank
    ciklus:
    mov     bl,[esi+ecx]
    shr     bl,4
    mov     dl,bl
    mov     bl,[esi+ecx]
    and     bl,0x0f
    mov     ah,[ebp+ebx]                         ;also  4 bit
    mov     al,[ebp+edx]                         ;felso 4 bit
    mov     edi,ecx
    shl     edi,1
    mov     [esi+edi+18],ax
    inc     cx
    cmp     cx,16
    jne     ciklus
    mov     byte [esi+edi+21],10
    mov     byte [esi+edi+22],0ah 
    mov     esi,18
    mov     eax,4                                ; 'write' system call = 4
    mov     ebx,1                                ; file descriptor 1 = STDOUT
    mov     ecx,[heap_base]                      ; string to write
    add     ecx,esi
    mov     edx,34                               ; length of string to write
    int     80h                                  ; call the kernel
    ret
vege:

                                                 ;Exit the program
mov eax, 1
xor ebx, ebx
int 0x80
