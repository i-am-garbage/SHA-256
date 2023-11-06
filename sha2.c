#include "sha2.h"
#include<stdlib.h>
#include<stdio.h>

unsigned int K[64] =
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

unsigned int A = 0x6a09e667, B = 0xbb67ae85, C = 0x3c6ef372, D = 0xa54ff53a, E = 0x510e527f, F = 0x9b05688c, G = 0x1f83d9ab, H = 0x5be0cd19;
unsigned int A0 = 0x6a09e667, B0 = 0xbb67ae85, C0 = 0x3c6ef372, D0 = 0xa54ff53a, E0 = 0x510e527f, F0 = 0x9b05688c, G0 = 0x1f83d9ab, H0 = 0x5be0cd19;


UChar HexToAscii(unsigned int c) {
	if (c > 9) {
		return (c + 55);
	}
	else {
		return (c + 48);
	}
}

int chartoword(unsigned char* Originaltext, int start)
{
	return((int)((Originaltext[start] & 0x000000ff) << 24) | (int)((Originaltext[start + 1] & 0x000000ff) << 16) | (int)((Originaltext[start + 2] & 0x000000ff) << 8) | (int)((Originaltext[start + 3] & 0x000000ff)));
}

void divide(unsigned char* Originaltext, unsigned int group[], int length)
{
	int temp = length / 4, l = length, llong = length / 64 + (length % 64) / 56;
	int i,j;
	while (l >= 0)
	{
		if (l / 4)
		{
			for (j = 0; j < temp; j++, l -= 4)
			{
				group[j] = chartoword(Originaltext, j * 4);
			}
		}
		else
		{
			Originaltext[temp * 4 + (l + 4) % 4] = 0x80;
			for (j = length + 1; j <= 3 + temp * 4; Originaltext[j] = 0, j++);
			group[temp] = chartoword(Originaltext, temp * 4);
			l -= 4;
		}
	}
	for (i = temp + 1; i < 15 + 16 * llong; i++)
	{
		group[i] = 0;
	}
}

void Getw(unsigned int w[], unsigned int group[], int llong)
{
	int i, j;
	for (i = 0; i < llong + 1; i++)
	{
		for (j = 0; j < 16; j++)
		{
			w[i * 64 + j] = group[i * 16 + j];
		}
		for (j = 16; j < 64; w[i * 64 + j++] = w[i * 64 + j - 7] + w[i * 64 + j - 16] + S1(w[i * 64 + j - 2]) + S0(w[i * 64 + j - 15]));
			
	}
}


unsigned int Step(unsigned int w[],int llong)
{
	int t,tt;
	unsigned int t1, t2;
	for (t = 0; t <= 63 + llong * 64; t++)
	{
		
		tt = t % 64;
		if (tt == 0 && t != 0)
		{
			A = A + A0;
			A0 = A;
			B = B + B0;
			B0 = B;
			C = C + C0;
			C0 = C;
			D = D + D0;
			D0 = D;
			E = E + E0;
			E0 = E;
			F = F + F0;
			F0 = F;
			G = G + G0;
			G0 = G;
			H = H + H0;
			H0 = H;
		}
		t1 = H + sigma1(E) + CH(E, F, G) + K[tt] + w[t];
		t2 = sigma0(A) + MAJ(A, B, C);
		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
		//printf("第%2d轮加密后的密文是%08X %08X %08X %08X %08X %08X %08X %08X\n", t + 1, A, B, C, D, E, F, G, H);    444
	}
	A = A + A0;
	B = B + B0;
	C = C + C0;
	D = D + D0;
	E = E + E0;
	F = F + F0;
	G = G + G0;
	H = H + H0;
}

UChar operation_sha2(unsigned char s[], UChar data[])
{
	unsigned int length = 0;
	int xx = 0;
	unsigned int w[N] = { 0 };
	for (int i = 0; s[i] != 0; i++, length++)
	{
		xx += 8;
		w[i] = 0;
	}
	unsigned int llong = length / 64 + (length % 64) / 56;
	//unsigned int* group = (int*)malloc(sizeof(int) * N);
	//unsigned int* group = (int*)malloc(sizeof(int) * N);
	unsigned int group[N] = { 0 };
	
	group[(llong + 1) * 16 - 1] = xx;
	divide(s, group, length);
	Getw(w, group, llong);
	Step(w, llong);
	
	unsigned int S[8] = { A, B, C, D, E, F, G, H };
	unsigned int temp;
	int bb = sizeof(S);
	for (int i = 0; i < sizeof(S) / 4; i++) {
		unsigned int aa = S[i];
		temp = (S[i] >> 28) & 0x0000000f;   // 取16进制数高位放到 HexToAscii 函数中转成字符
		*(data + 8 * i) = HexToAscii(temp);
		temp = S[i] & 0x0f000000;   // 取16进制数低位放到 HexToAscii 函数中转成字符
		*(data + i * 8 + 1) = HexToAscii(temp >> 24);
		temp = S[i] & 0x00f00000;
		*(data + i * 8 + 2) = HexToAscii(temp >> 20);
		temp = S[i] & 0x000f0000;
		*(data + i * 8 + 3) = HexToAscii(temp >> 16);
		temp = S[i] & 0x0000f000;
		*(data + i * 8 + 4) = HexToAscii(temp >> 12);
		temp = S[i] & 0x00000f00;
		*(data + i * 8 + 5) = HexToAscii(temp >> 8);
		temp = S[i] & 0x000000f0;
		*(data + i * 8 + 6) = HexToAscii(temp >> 4);
		temp = S[i] & 0x0000000f;
		*(data + i * 8 + 7) = HexToAscii(temp);
	}
	return data;
}
