/*************************************************************************************/
/* base64.c                                                                          */
/* NTLMMessageDecoder                                                                */
/*                                                                                   */
/* Routines for decoding base64 text.                                                */
/*                                                                                   */
/* Written by Heath Raftery, 2008                                                    */
/* Email: heath@hrsoftworks.net           Web: http://heath.hrsoftworks.net          */
/*                                                                                   */
/* This work is licensed under the Creative Commons Attribution 2.5 License.         */
/* To view a copy of this license, visit http://creativecommons.org/licenses/by/2.5/ */
/* or send a letter to Creative Commons, 543 Howard Street, 5th Floor,               */
/* San Francisco, California, 94105, USA.                                            */
/*************************************************************************************/

#include <stdlib.h>

#include "base64.h"

// decode 4 '6-bit' characters into 3 8-bit binary bytes
void decodeBlock( unsigned char in[4], unsigned char out[3] )
{
  out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
  out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
  out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

// decode an arbitrary string
char* decodeString(char *inString, int *length)
{
  unsigned char in[4], out[3], v;
  char *decoded;
  int i, len, enc = 0, dec = 0;

  decoded = (char *)malloc( (*length) * sizeof(char) );

  while(enc<=*length)
  {
    for(len = 0, i = 0; i < 4 && enc<=*length; i++)
    {
      v = 0;
      while(enc<=*length && v == 0 )
      {
        v = inString[enc++];
        v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
        if(v)
          v = (unsigned char) ((v == '$') ? 0 : v - 61);
      }
      if(enc<=*length)
      {
        len++;
        if(v)
          in[i] = (unsigned char) (v - 1);
      }
      else
        in[i] = 0;
    }
    if(len)
    {
      decodeBlock(in, out);
      for(i = 0; i < len - 1; i++)
        decoded[dec++] = out[i];
    }
  }
  *length = dec;

  return decoded;
}

