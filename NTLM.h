/*************************************************************************************/
/* NTLM.h                                                                            */
/* NTLMMessageDecoder                                                                */
/*                                                                                   */
/* NTLM structs and defines.                                                         */
/*                                                                                   */
/* Written by Heath Raftery, 2008                                                    */
/* Email: heath@hrsoftworks.net           Web: http://heath.hrsoftworks.net          */
/*                                                                                   */
/* This work is licensed under the Creative Commons Attribution 2.5 License.         */
/* To view a copy of this license, visit http://creativecommons.org/licenses/by/2.5/ */
/* or send a letter to Creative Commons, 543 Howard Street, 5th Floor,               */
/* San Francisco, California, 94105, USA.                                            */
/*************************************************************************************/


struct securityBuffer
{
  short   length;
  short   length2;            //actually space allocated, but almost always == length
  long    offset;
};

struct type1Message
{
  char    protocol[8];        // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
  long    type;               // 0x01
  long    flags;              // 0xb203

  struct securityBuffer domain;

                              // NOTE: host also called workstation in newer docs. Ah, the joys of reverse engineering
                              //  a protocol based on such poorly defined concepts as a "workstation"! "Host" is shorter anyway.
  struct securityBuffer host; // host string offset (always 0x20)

//  char    host[*];       // host string (ASCII)
//  char    dom[*];        // domain string (ASCII)
};

struct type2Message
{
  char    protocol[8];          // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
  long    type;                 // 0x02

  struct securityBuffer target; // offset 0x28

  long    flags;                // 0x8201
  char    nonce[8];             // nonce
  char    context[8];           // context
  struct securityBuffer targetInfo;
};

struct type3Message
{
  char    protocol[8];              // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
  long    type;                     // 0x03

  struct securityBuffer LMResponse; //length always 0x18
  struct securityBuffer NTResponse; //length always 0x18
  struct securityBuffer domain;     //offset always 0x40
  struct securityBuffer username;
  struct securityBuffer host;       //NOTE: again, called "workstation" in some texts
  struct securityBuffer sessionKey; //0, 0, message length

  long   flags;                     // 0x8201

//  char    dom[*];          // domain string (unicode UTF-16LE)
//  char    user[*];         // username string (unicode UTF-16LE)
//  char    host[*];         // host string (unicode UTF-16LE)
//  char    lm_resp[*];      // LanManager response
//  char    nt_resp[*];      // NT response
};

#define NTLM_FLAG_NEGOTIATE_UNICODE               0x00000001  //Indicates that Unicode strings are supported for use in security buffer data.
#define NTLM_FLAG_NEGOTIATE_OEM                   0x00000002  //Indicates that OEM strings are supported for use in security buffer data.
#define NTLM_FLAG_REQUEST_TARGET                  0x00000004  //Requests that the server's authentication realm be included in the Type 2 message.
#define NTLM_FLAG_UNKNOWN1                        0x00000008  //This flag's usage has not been identified.
#define NTLM_FLAG_NEGOTIATE_SIGN                  0x00000010  //Specifies that authenticated communication between the client and server should carry a digital signature (message integrity).
#define NTLM_FLAG_NEGOTIATE_SEAL                  0x00000020  //Specifies that authenticated communication between the client and server should be encrypted (message confidentiality).
#define NTLM_FLAG_NEGOTIATE_DATAGRAM_STYLE        0x00000040  //Indicates that datagram authentication is being used.
#define NTLM_FLAG_NEGOTIATE_LAN_MANAGER_KEY       0x00000080  //Indicates that the LAN Manager session key should be used for signing and sealing authenticated communications.
#define NTLM_FLAG_NEGOTIATE_NETWARE               0x00000100  //This flag's usage has not been identified.
#define NTLM_FLAG_NEGOTIATE_NTLM                  0x00000200  //Indicates that NTLM authentication is being used.
#define NTLM_FLAG_UNKNOWN2                        0x00000400  //This flag's usage has not been identified.
#define NTLM_FLAG_UNKNOWN3                        0x00000800  //This flag's usage has not been identified.
#define NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED       0x00001000  //Sent by the client in the Type 1 message to indicate that the name of the domain in which the client workstation has membership is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
#define NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED  0x00002000  //Sent by the client in the Type 1 message to indicate that the client workstation's name is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
#define NTLM_FLAG_NEGOTIATE_LOCAL_CALL            0x00004000  //Sent by the server to indicate that the server and client are on the same machine. Implies that the client may use the established local credentials for authentication instead of calculating a response to the challenge.
#define NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN           0x00008000  //Indicates that authenticated communication between the client and server should be signed with a "dummy" signature.
#define NTLM_FLAG_TARGET_TYPE_DOMAIN              0x00010000  //Sent by the server in the Type 2 message to indicate that the target authentication realm is a domain.
#define NTLM_FLAG_TARGET_TYPE_SERVER              0x00020000  //Sent by the server in the Type 2 message to indicate that the target authentication realm is a server.
#define NTLM_FLAG_TARGET_TYPE_SHARE               0x00040000  //Sent by the server in the Type 2 message to indicate that the target authentication realm is a share. Presumably, this is for share-level authentication. Usage is unclear.
#define NTLM_FLAG_NEGOTIATE_NTLM2_KEY             0x00080000  //Indicates that the NTLM2 signing and sealing scheme should be used for protecting authenticated communications. Note that this refers to a particular session security scheme, and is not related to the use of NTLMv2 authentication. This flag can, however, have an effect on the response calculations (as detailed in the "NTLM2 Session Response" section).
#define NTLM_FLAG_REQUEST_INIT_RESPONSE           0x00100000  //This flag's usage has not been identified.
#define NTLM_FLAG_REQUEST_ACCEPT_RESPONSE         0x00200000  //This flag's usage has not been identified.
#define NTLM_FLAG_REQUEST_NON_NT_SESSION_KEY      0x00400000  //This flag's usage has not been identified.
#define NTLM_FLAG_NEGOTIATE_TARGET_INFO           0x00800000  //Sent by the server in the Type 2 message to indicate that it is including a Target Information block in the message. The Target Information block is used in the calculation of the NTLMv2 response.
#define NTLM_FLAG_UNKNOWN4                        0x01000000  //This flag's usage has not been identified.
#define NTLM_FLAG_UNKNOWN5                        0x02000000  //This flag's usage has not been identified.
#define NTLM_FLAG_UNKNOWN6                        0x04000000  //This flag's usage has not been identified.
#define NTLM_FLAG_UNKNOWN7                        0x08000000  //This flag's usage has not been identified.
#define NTLM_FLAG_UNKNOWN8                        0x10000000  //This flag's usage has not been identified.
#define NTLM_FLAG_NEGOTIATE_128                   0x20000000  //Indicates that 128-bit encryption is supported.
#define NTLM_FLAG_NEGOTIATE_KEY_EXCHANGE          0x40000000  //Indicates that the client will provide an encrypted master session key in the "Session Key" field of the Type 3 message. This is used in signing and sealing, and is RC4-encrypted using the previous session key as the encryption key.
#define NTLM_FLAG_NEGOTIATE_56                    0x80000000  //Indicates that 56-bit encryption is supported.

