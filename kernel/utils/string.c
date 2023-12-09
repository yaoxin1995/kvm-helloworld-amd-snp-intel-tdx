#include <utils/string.h>

/* no memory accessibility checks in these string functions */

uint64_t strlen(const char *s) {
  return strnlen(s, (1ull << 63) - 1);
}

uint64_t strnlen(const char *s, uint64_t maxlen) {
  uint64_t i = 0;
  while(i < maxlen) {
    if(*s == 0) return i;
    i++; s++;
  }
  return maxlen;
}

void *memset(void *b, int c, uint64_t len) {
  for(int i=0;i<len;i++)
    ((uint8_t*)b)[i] = (uint8_t)c;
  return b;
}

void *memcpy(void *dst, const void *src, uint64_t n) {
  asm(
    "mov rcx, %[n];"
    "rep movsb byte ptr [%[dst]], byte ptr [%[src]];"
    :: [n]"r"(n), [dst]"D"(dst), [src]"S"(src) : "rcx"
    );
  return dst;
}

int memcmp(const void *s1, const void *s2, uint64_t n) {
  unsigned char u1, u2;
  for(; n--; s1++, s2++) {
    u1 = *(unsigned char *) s1;
    u2 = *(unsigned char *) s2;
    if (u1 != u2) return u1 - u2;
  }
  return 0;
}

void HexToAscii(unsigned char *pHex, unsigned char *pAscii, int nLen)
{
    unsigned char Nibble[2];
    unsigned int i,j;
    for (i = 0; i < nLen; i++){
        Nibble[0] = (pHex[i] & 0xF0) >> 4;
        Nibble[1] = pHex[i] & 0x0F;
        for (j = 0; j < 2; j++){
            if (Nibble[j] < 10){            
                Nibble[j] += 0x30;
            }
            else{
                if (Nibble[j] < 16)
                    Nibble[j] = Nibble[j] - 10 + 'A';
            }
            *pAscii++ = Nibble[j];
        }               
    }           
}

void uint64_to_string(uint64_t num,unsigned char* string){
  HexToAscii((unsigned char *)&num,string,8);
  for(int i=0;i<4;i++){
    for(int j=0;j<2;j++){
        char c = string[i*2+j];
        string[i*2+j] = string[(7-i)*2+j];
        string[(7-i)*2+j] = c;
    }
  }
}