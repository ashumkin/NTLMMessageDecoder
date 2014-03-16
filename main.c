/*************************************************************************************/
/* main.c                                                                            */
/* NTLMMessageDecoder                                                                */
/*                                                                                   */
/* Main source file for NTLMMessageDecoder.                                          */
/* Takes on stdin a base64 encoded NTLM proxy authentication message (type 1, 2,     */
/* or 3) and spits out on stdout the deconstruction of the message.                  */
/*                                                                                   */
/* Written by Heath Raftery, 2008                                                    */
/* Email: heath@hrsoftworks.net           Web: http://heath.hrsoftworks.net          */
/*                                                                                   */
/* This work is licensed under the Creative Commons Attribution 2.5 License.         */
/* To view a copy of this license, visit http://creativecommons.org/licenses/by/2.5/ */
/* or send a letter to Creative Commons, 543 Howard Street, 5th Floor,               */
/* San Francisco, California, 94105, USA.                                            */
/*************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTLM.h"
#include "base64.h"

short ltohs(short in) { return in; } //little endian to host endianess, short
long  ltohl(long in)  { return in; } //little endian to host endianess, long

void PrintFlags(long flags);
void PrintSecurityBuffer(char *data, struct securityBuffer buf);
void PrintString(char *str, int len);

int main(int argc, char *argv[])
{
    char buf[500], *decBuf;
    int i=0, c;

    while( (c=getchar()) != EOF)
    {
        if(c != '\n' && c != '\r')
            buf[i++] = c;
    }

    if(i==0)
    {
        printf("No input provided on stdin. Exiting.\n");
        return 1;
    }

    decBuf = decodeString(buf, &i);

    if(strcmp(decBuf, "NTLMSSP") == 0)
    {
        short datas=0;
        long flags=0;
        struct type1Message *msg1 = (struct type1Message*)decBuf;
        struct type2Message *msg2 = (struct type2Message*)decBuf;
        struct type3Message *msg3 = (struct type3Message*)decBuf;

        switch(ltohs(msg1->type))
        {
            case 0x01: //type 1
                printf("Type 1\n");
                PrintFlags(msg1->flags);
                printf("Domain: ");
                PrintSecurityBuffer(decBuf, msg1->domain);
                printf("\n");
                printf("Host: ");
                PrintSecurityBuffer(decBuf, msg1->host);
                printf("\n");
                break;

            case 0x02: //type 2
                printf("Type 2\n");
                PrintFlags(msg2->flags);
                printf("Target: ");
                PrintSecurityBuffer(decBuf, msg2->target);
                printf("\n");
                printf("Nonce: ");
                PrintString(msg2->nonce, 8);
                printf("\n");
                printf("Context: ");
                PrintString(msg2->context, 8);
                printf("\n");
                printf("Target Info: ");
                PrintSecurityBuffer(decBuf, msg2->targetInfo);
                printf("\n");
                break;

            case 0x03: //type 3
                printf("Type 3\n");
                PrintFlags(msg3->flags);
                printf("LMResponse: ");
                PrintSecurityBuffer(decBuf, msg3->LMResponse);
                printf("\n");
                printf("NTResponse: ");
                PrintSecurityBuffer(decBuf, msg3->NTResponse);
                printf("\n");
                printf("Domain: ");
                PrintSecurityBuffer(decBuf, msg3->domain);
                printf("\n");
                printf("Username: ");
                PrintSecurityBuffer(decBuf, msg3->username);
                printf("\n");
                printf("Host: ");
                PrintSecurityBuffer(decBuf, msg3->host);
                printf("\n");
                printf("Session Key: ");
                PrintSecurityBuffer(decBuf, msg3->sessionKey);
                printf("\n");
                break;

            default:
                printf("Unrecognised type: 0x%X\n", ltohl(msg1->type));
                break;
        }
    }
    else
        printf("Unable to determine message type.");

    return 0;
}

void PrintFlags(long flags)
{
    flags = ltohl(flags);
    if(flags & NTLM_FLAG_NEGOTIATE_UNICODE)
        printf("NTLM Flag: Negotiate Unicode\n");
    if(flags & NTLM_FLAG_NEGOTIATE_OEM)
        printf("NTLM Flag: Negotiate OEM\n");
    if(flags & NTLM_FLAG_REQUEST_TARGET)
        printf("NTLM Flag: Request Target\n");
    if(flags & NTLM_FLAG_UNKNOWN1)
        printf("NTLM Flag: Unknown1\n");
    if(flags & NTLM_FLAG_NEGOTIATE_SIGN)
        printf("NTLM Flag: Negotiate Sign\n");
    if(flags & NTLM_FLAG_NEGOTIATE_SEAL)
        printf("NTLM Flag: Negotiate Seal\n");
    if(flags & NTLM_FLAG_NEGOTIATE_DATAGRAM_STYLE)
        printf("NTLM Flag: Negotiate Datagram Style\n");
    if(flags & NTLM_FLAG_NEGOTIATE_LAN_MANAGER_KEY)
        printf("NTLM Flag: Negotiate LAN Manager Key\n");
    if(flags & NTLM_FLAG_NEGOTIATE_NETWARE)
        printf("NTLM Flag: Negotiate Netware\n");
    if(flags & NTLM_FLAG_NEGOTIATE_NTLM)
        printf("NTLM Flag: Negotiate NTLM\n");
    if(flags & NTLM_FLAG_UNKNOWN2)
        printf("NTLM Flag: Unknown2\n");
    if(flags & NTLM_FLAG_UNKNOWN3)
        printf("NTLM Flag: Unknown3\n");
    if(flags & NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED)
        printf("NTLM Flag: Negotiate Domain Supplied\n");
    if(flags & NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED)
        printf("NTLM Flag: Negotiate Workstation Supplied\n");
    if(flags & NTLM_FLAG_NEGOTIATE_LOCAL_CALL)
        printf("NTLM Flag: Negotiate Local Call\n");
    if(flags & NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN)
        printf("NTLM Flag: Negotiate Always Sign\n");
    if(flags & NTLM_FLAG_TARGET_TYPE_DOMAIN)
        printf("NTLM Flag: Target Type Domain\n");
    if(flags & NTLM_FLAG_TARGET_TYPE_SERVER)
        printf("NTLM Flag: Target Type Server\n");
    if(flags & NTLM_FLAG_TARGET_TYPE_SHARE)
        printf("NTLM Flag: Target Type Share\n");
    if(flags & NTLM_FLAG_NEGOTIATE_NTLM2_KEY)
        printf("NTLM Flag: Negotiate NTLM2 Key\n");
    if(flags & NTLM_FLAG_REQUEST_INIT_RESPONSE)
        printf("NTLM Flag: Request Init Response\n");
    if(flags & NTLM_FLAG_REQUEST_ACCEPT_RESPONSE)
        printf("NTLM Flag: Request Accept Response\n");
    if(flags & NTLM_FLAG_REQUEST_NON_NT_SESSION_KEY)
        printf("NTLM Flag: Request Non-NT Session Key\n");
    if(flags & NTLM_FLAG_NEGOTIATE_TARGET_INFO)
        printf("NTLM Flag: Negotiate Target Info\n");
    if(flags & NTLM_FLAG_UNKNOWN4)
        printf("NTLM Flag: UNKNOWN4\n");
    if(flags & NTLM_FLAG_UNKNOWN5)
        printf("NTLM Flag: UNKNOWN5\n");
    if(flags & NTLM_FLAG_UNKNOWN6)
        printf("NTLM Flag: UNKNOWN6\n");
    if(flags & NTLM_FLAG_UNKNOWN7)
        printf("NTLM Flag: UNKNOWN7\n");
    if(flags & NTLM_FLAG_UNKNOWN8)
        printf("NTLM Flag: UNKNOWN8\n");
    if(flags & NTLM_FLAG_NEGOTIATE_128)
        printf("NTLM Flag: Negotiate 128\n");
    if(flags & NTLM_FLAG_NEGOTIATE_KEY_EXCHANGE)
        printf("NTLM Flag: Negotiate Key Exchange\n");
    if(flags & NTLM_FLAG_NEGOTIATE_56)
        printf("NTLM Flag: Negotiate 56\n");
}

void PrintSecurityBuffer(char *data, struct securityBuffer buf)
{
  PrintString(&(data[ltohl(buf.offset)]), ltohs(buf.length));
}

void PrintString(char *str, int len)
{
  char *buf = malloc(len+1);
  int i;
  for(i=0; i<len; i++)
  {
    char c = str[i];
    if(isprint(c))
      buf[i] = c;
    else
      buf[i] = '.';
  }
  buf[i] = '\0';

  printf("%s", buf);

  free(buf);
}

