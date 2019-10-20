/* ecc.c 
 * ECC functions (this is from skyeye-starlet); thanks segher :^)
 */

#include "ecc.h"
#include <string.h>

// ecc code based on segher's unecc.c
static u8 parity(u8 x) 
{
	u8 y = 0;
	while (x) 
	{
		y ^= (x & 1);
		x >>= 1;
	}
	return y;
}

//static void calc_ecc(u8 *data, u8 *ecc)
void calc_ecc(u8 *data, u8 *ecc)
{
	//u32 ecc = 0;
	u8 a[12][2];
	int i, j;
	u32 a0, a1;
	u8 x;

	memset(a, 0, 12*2);
	for (i = 0; i < 512; i++) 
	{
        x = data[i];
        for (j = 0; j < 9; j++)
		a[3+j][(i >> j) & 1] ^= x;
	}

	x = a[3][0] ^ a[3][1];
	a[0][0] = x & 0x55;
	a[0][1] = x & 0xaa;
	a[1][0] = x & 0x33;
	a[1][1] = x & 0xcc;
	a[2][0] = x & 0x0f;
	a[2][1] = x & 0xf0;

	for (j = 0; j < 12; j++)
	{
		a[j][0] = parity(a[j][0]);
		a[j][1] = parity(a[j][1]);
	}

	a0 = a1 = 0;
	for (j = 0; j < 12; j++)
	{
		a0 |= a[j][0] << j;
		a1 |= a[j][1] << j;
	}

	ecc[0] = a0;
	ecc[1] = a0 >> 8;
	ecc[2] = a1;
	ecc[3] = a1 >> 8;
	
	//return (a0 << 24 | (a0 >> 8) << 16 | a1 << 8 | (a1 >> 8));
}
