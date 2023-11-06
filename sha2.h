#pragma once
#ifndef SHA2_H_INCLUDED
#define SHA2_H_INCLUDED
#define N 300000

#define ROTR(x, n)   ((x >> n) | (x << (32 - n)))
#define S0(x) ((ROTR(x, 7)) ^ (ROTR(x, 18)) ^ ((x) >> 3))
#define S1(x) ((ROTR(x, 17)) ^ (ROTR(x, 19)) ^ ((x) >> 10))
#define sigma0(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define sigma1(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

typedef unsigned char   UChar;
UChar HexToAscii(unsigned int c);
int chartoword(unsigned char* Originaltext, int start);
void divide(unsigned char* Originaltext, int* group, int length);
void Getw(unsigned int w[], unsigned int group[], int llong);
unsigned int Step(unsigned int w[], int t);



#endif 