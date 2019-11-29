#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>


#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
#define M 64 //Number of bits in Bloom Filter
#define K 4 //Number of bits set per mapping in Bloom Filter


char BFilter[M/8];
unsigned int NumBytes;
uint32_t FNV32(const char *s);

void mapBloom_FNV(uint32_t hash);
void mapBloom_mhash(uint32_t hashkey);

uint32_t testBloom_FNV(uint32_t hash);
uint32_t testBloom_mhash(uint32_t hashkey);

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);

/*
 * Main Function
 */

 int main(int agrc, char *argv[]){
	 FILE *fp1;
	 FILE *fp2;
	 char inFile1[256];
	 char inFile2[256];
	 char inString[1024];
	 const char *key;
	 const char *teststring;
	 //unsigned int crc32;
	 uint32_t retCode1;
	 uint32_t retCode2;
	 unsigned int i;
	 uint32_t fnvhash;
	 uint32_t mhash32;

	printf("------------------------------------------------------------\n");
	printf("Bloom Filter\n");
	printf("------------------------------------------------------------\n");

	//Determine number of Bytes in Bloom Filter
	NumBytes = M/8;
	if((M%8)!=0)
	{
		printf("****Error - M value must be divisible by 8 \n");
		exit(1);
	}

	//Clears the Bloom Filter
	for(i=0;i<NumBytes;i++)
		BFilter[i] = 0x00;


	printf("File name of Malicious URL dataset ==>");
	scanf("%s",&inFile1);
	fp1 = fopen(inFile1,"r");
	if(fp1 == NULL)
	{
		printf("Error in opening File #1 %s \n",inFile1);
		exit(1);
	}

	printf("File name of input list to check for match ==>");
	scanf("%s",&inFile2);
	fp2 = fopen(inFile2,"r");
	if(fp2 == NULL)
	{
		printf("Error in opening File #2 %s \n",inFile2);
		exit(1);
	}

	while(1){
		fgets(inString,1024,fp1);
		if (feof(fp1))
		break;

		for(i=0;i<K;i++)
		{
			
			key = inString;
			teststring = inString;
			mhash32 = murmur3_32(key, (uint32_t) strlen(key),0);
			fnvhash = FNV32(teststring);
			mapBloom_FNV(fnvhash);
			mapBloom_mhash(mhash32);
		}
	}
	fclose(fp1);

	//Output of the Bloom Filter
	printf("------------------------------------------------------------\n");
	printf("Bloom filter is (M= %d bits and K = %d mapping)...\n ", M, K);

	for (i=0; i<NumBytes;i++)
		printf("%2d", i);

	printf("\n");

	for (i=0;i<NumBytes;i++)
		printf("%02X", BFilter[i]);

	printf("\n");
	// Output results header
	printf("--------------------------------------------------------------\n");


	while(1)
	{
		fgets(inString, 1024, fp2);
		if(feof(fp2))
			break;

		for(i =0; i<K ; i++)
		{
			
			mhash32 = murmur3_32(key, (uint32_t) strlen(key),0);
			fnvhash = FNV32(teststring);
			retCode1 = testBloom_FNV(fnvhash);
			retCode2 = testBloom_mhash(mhash32);
			if(retCode1 == 0 || retCode2 == 0){
				printf("%s is not Malicious",inString);
				break;
			}
		}

	if(retCode1==1 && retCode2==1)
		printf("%s may be Malicious\n", inString);

	}
	fclose(fp2);
}

uint32_t FNV32(const char *s)
{
    uint32_t hashi = FNV_OFFSET_32, i;
    for(i = 0; i < strlen(s); i++)
    {
        hashi = hashi ^ (s[i]); // xor next byte into the bottom of the hash
        hashi = hashi * FNV_PRIME_32; // Multiply by prime number found to work well
    }
    return hashi;
}


	uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	uint32_t h = seed;
	if (len > 3) {
		size_t i = len >> 2;
		do {
			uint32_t k;
			memcpy(&k, key, sizeof(uint32_t));
			key += sizeof(uint32_t);
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h = h * 5 + 0xe6546b64;
		} while (--i);
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		do {
			k <<= 8;
			k |= key[i - 1];
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}


void mapBloom_mhash(uint32_t hashkey)
{
	int tempInt;
	int bitNum;
	int byteNum;
	unsigned char mapBit;
	tempInt = hashkey % M;
	byteNum = tempInt / 8;
	bitNum = tempInt % 8;

	mapBit = 0x80;
	mapBit = mapBit >> bitNum;

	// Map the bit into the Bloom Filter
	BFilter[byteNum] = BFilter[byteNum] | mapBit;
}

void mapBloom_FNV(uint32_t hash)
{
	int tempInt;
	int bitNum;
	int byteNum;
	unsigned char mapBit;
	tempInt = hash % M;
	byteNum = tempInt / 8;
	bitNum = tempInt % 8;

	mapBit = 0x80;
	mapBit = mapBit >> bitNum;

	// Map the bit into the Bloom Filter
	BFilter[byteNum] = BFilter[byteNum] | mapBit;
}
// Function to test for a Bloom Filter Match

uint32_t testBloom_mhash(uint32_t hashkey)
{
	int tempInt;
	int bitNum;
	int byteNum;
	unsigned char testBit;
	int retCode;
	tempInt = hashkey % M;
	byteNum = tempInt / 8;
	bitNum = tempInt % 8;

	testBit = 0x80;
	testBit = testBit >> bitNum;
	if (BFilter[byteNum] & testBit)
		retCode = 1;
	else
		retCode = 0;

	return retCode;
}

uint32_t testBloom_FNV(uint32_t hash)
{
	int tempInt;
	int bitNum;
	int byteNum;
	unsigned char testBit;
	int retCode;
	tempInt = hash % M;
	byteNum = tempInt / 8;
	bitNum = tempInt % 8;

	testBit = 0x80;
	testBit = testBit >> bitNum;
	if (BFilter[byteNum] & testBit)
		retCode = 1;
	else
		retCode = 0;

	return retCode;
}

