/*************************************************************************************/             /* base64.h                                                                          */             /* NTLMMessageDecoder                                                                */
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

//exported function
char* decodeString(char *inString, int *length);

//decode dictionary
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
