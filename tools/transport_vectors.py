"""Execute extracted pinned Stable C packet writers; never import Kotlin.

Uses upstream embedded AEAD and a local OpenSSL DLL for SHA1/RC4 primitives.
On Windows the Git for Windows libcrypto DLL is used (no network dependency).
Synthetic fixed randomness is only for reproducible fixtures.
"""
from pathlib import Path
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "SoftEtherVPN_Stable/src"

def function(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]

encrypt = (SRC / "Mayaqua/Encrypt.c").read_text(encoding="utf-8-sig")
memory = (SRC / "Mayaqua/Memory.c").read_text(encoding="utf-8-sig")
network = (SRC / "Mayaqua/Network.c").read_text(encoding="utf-8-sig")
udp = (SRC / "Cedar/UdpAccel.c").read_text(encoding="utf-8-sig")
start = encrypt.index("/*", encrypt.index("//// RFC 8439"))
embedded = encrypt[start:encrypt.index("// OpenSSL 3.0.0", start)]
stub = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <windows.h>
typedef uint32_t UINT; typedef uint64_t UINT64; typedef unsigned char UCHAR;
typedef unsigned short USHORT; typedef int bool;
#define true 1
#define false 0
#define SHA1_SIZE 20
#define MAX_SIZE 256
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define Copy(d,s,n) memcpy(d,s,n)
#define Zero(d,n) memset(d,0,n)
#define Malloc(n) malloc(n)
#define ZeroMalloc(n) calloc(1,n)
#define Free(p) free(p)
#define Debug(...)
#define WHERE
#define rand() 0
#define AEAD_CHACHA20_POLY1305_MAC_SIZE 16
int IsBigEndian(void) { return false; }
int Cmp(void *a, void *b, UINT n) { return memcmp(a,b,n); }
void XorData(void *dst, void *a, void *b, UINT n) { for(UINT i=0;i<n;i++) ((UCHAR*)dst)[i]=((UCHAR*)a)[i]^((UCHAR*)b)[i]; }
UINT Endian32(UINT x) { return _byteswap_ulong(x); }
UINT64 Endian64(UINT64 x) { return _byteswap_uint64(x); }
USHORT Endian16(USHORT x) { return _byteswap_ushort(x); }
void write64(void *p, UINT64 x) { x=Endian64(x); Copy(p,&x,8); }
void write32(void *p, UINT x) { x=Endian32(x); Copy(p,&x,4); }
#define WRITE_UINT64(p,x) write64(p,x)
#define WRITE_UINT(p,x) write32(p,x)
UINT StrLen(char *s) { return (UINT)strlen(s); }
USHORT Rand16(void) { return 0x1233; }
UINT Rand32(void) { return 0; }
UCHAR Rand8(void) { return 1; }
void Rand(void *p, UINT n) { for(UINT i=0;i<n;i++) ((UCHAR*)p)[i]=(UCHAR)i; }
void BinToStr(char *s, UINT cap, void *p, UINT n) { (void)cap; for(UINT i=0;i<n;i++) sprintf(s+2*i,"%02x",((UCHAR*)p)[i]); }
void StrLower(char *p) { (void)p; }
typedef struct rc4_key_st { UINT x,y,data[256]; } RC4_KEY;
typedef struct { RC4_KEY *Rc4Key; } CRYPT;
static HMODULE crypto;
void HashSha1(void *dst, void *src, UINT n) {
    unsigned char *(*f)(const unsigned char*,size_t,unsigned char*)=(void*)GetProcAddress(crypto,"SHA1");
    if(!f) abort(); f(src,n,dst);
}
void RC4_set_key(RC4_KEY *k, int n, const UCHAR *p) { void(*f)(RC4_KEY*,int,const UCHAR*)=(void*)GetProcAddress(crypto,"RC4_set_key"); if(!f) abort(); f(k,n,p); }
void RC4(RC4_KEY *k, size_t n, void *p, void *dst) { void(*f)(RC4_KEY*,size_t,void*,void*)=(void*)GetProcAddress(crypto,"RC4"); if(!f) abort(); f(k,n,p,dst); }
typedef struct { UCHAR bytes[4096]; UINT Size; void *Buf; } BUF;
BUF *NewBuf(void) { BUF *b=calloc(1,sizeof(BUF)); b->Buf=b->bytes; return b; }
void WriteBuf(BUF *b, void *p, UINT n) { if(n>4096-b->Size) abort(); Copy(b->bytes+b->Size,p,n); b->Size+=n; }
void FreeBuf(BUF *b) { free(b); }
typedef struct { UINT count; void *items[64]; } LIST;
#define LIST_NUM(l) ((l)?(l)->count:0)
#define LIST_DATA(l,i) ((l)->items[i])
LIST *NewListFast(void *p) { (void)p; return calloc(1,sizeof(LIST)); }
void Add(LIST *l,void *p) { l->items[l->count++]=p; }
void Delete(LIST *l,void *p) { for(UINT i=0;i<l->count;i++) if(l->items[i]==p) { memmove(l->items+i,l->items+i+1,(--l->count-i)*sizeof(void*)); break; } }
void ReleaseList(LIST *l) { Free(l); }
typedef struct { int unused; } IP;
typedef struct { bool IgnoreSendErr; } SOCK;
typedef struct { UINT Version; bool PlainTextMode,FatalError; UCHAR TmpBuf[2048],NextIv[20],NextIv_V2[12],MyKey[20],MyKey_V2[128]; UINT YourCookie,YourPort,YourPortByNatTServer; UINT64 Now,LastRecvYourTick; IP YourIp,YourIp2; SOCK *UdpSock; } UDP_ACCEL;
#define UDP_ACCELERATION_PACKET_KEY_SIZE_V1 20
#define UDP_ACCELERATION_COMMON_KEY_SIZE_V1 20
#define UDP_ACCELERATION_PACKET_IV_SIZE_V1 20
#define UDP_ACCELERATION_PACKET_IV_SIZE_V2 12
#define UDP_ACCELERATION_PACKET_MAC_SIZE_V2 16
#define UDP_ACCELERATION_MAX_PADDING_SIZE 32
#define UDP_ACCELERATION_TMP_BUF_SIZE 2048
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool b) { return true; }
void SetSockHighPriority(SOCK *s,bool b) {}
int IsZeroIP(IP *p) { return true; }
int CmpIpAddr(IP *p,IP *q) { return 0; }
static UCHAR captured[4096]; static UINT captured_size;
UINT SendTo(SOCK *s, IP *ip, UINT port, void *p, UINT n) { Copy(captured,p,n); captured_size=n; return n; }
#define RUDP_MAX_SEGMENT_SIZE 512
#define RUDP_MAX_NUM_ACK 64
#define RUDP_MAX_PACKET_SIZE 1355
#define RUDP_PROTOCOL_ICMP 1
#define RUDP_PROTOCOL_DNS 2
typedef struct { bool ServerMode; UINT Protocol; UINT64 Now; UCHAR SvcNameHash[20]; } RUDP_STACK;
typedef struct { UCHAR Key_Send[20],NextIv[20]; LIST *ReplyAckList; UINT64 YourTick,LastRecvCompleteSeqNo,LastSentTick; UINT Icmp_Type,YourPort; USHORT Dns_TranId; IP YourIp; } RUDP_SESSION;
void RUDPSendPacket(RUDP_STACK *r,IP *ip,UINT port,void *p,UINT n,UINT type) { Copy(captured,p,n); captured_size=n; }
typedef struct { void *Data; UINT Size,Type; } UDPPACKET;
void printhex(char *name,void *p,UINT n) { printf("%s=",name);for(UINT i=0;i<n;i++) printf("%02x",((UCHAR*)p)[i]);puts(""); }
'''
pieces = [function(memory, "bool WriteBufInt(BUF *b, UINT value)"),
          function(memory, "bool WriteBufStr(BUF *b, char *str)"),
          function(encrypt, "CRYPT *NewCrypt(void *key, UINT size)"),
          function(encrypt, "void FreeCrypt(CRYPT *c)"),
          function(encrypt, "void Encrypt(CRYPT *c, void *dst, void *src, UINT size)"),
          embedded,
          function(encrypt, "void Aead_ChaCha20Poly1305_Ietf_Encrypt_Embedded("),
          "#define Aead_ChaCha20Poly1305_Ietf_Encrypt Aead_ChaCha20Poly1305_Ietf_Encrypt_Embedded\n",
          function(udp, "void UdpAccelCalcKey(UCHAR *key, UCHAR *common_key, UCHAR *iv)"),
          function(udp, "void UdpAccelSend(UDP_ACCEL *a,"),
          function(network, "void RUDPSendSegmentNow(RUDP_STACK *r,")]
# Execute the exact upstream DNS writer block, including native ushort ID.
dns_start = network.index("BUF *b = NewBuf();", network.index("// In case of over DNS protocol") - 60)
dns_end = network.index("Free(p->Data);", dns_start)
dns = "void dns_packet(RUDP_STACK *r, UDPPACKET *p) {\n" + network[dns_start:dns_end] + "printhex(r->ServerMode ? \"dns_response\" : \"dns_query\",b->Buf,b->Size);FreeBuf(b);}\n"
derive_start = network.index("b = NewBuf();", network.index("// Generate the two keys", network.index("RUDP_SESSION *RUDPNewSession")))
derive_end = network.index("if (server_mode == false)", derive_start)
derive = network[derive_start:derive_end].replace("se->Magic_KeepAliveRequest", "keep_request").replace("se->Magic_KeepAliveResponse", "keep_response")
main = r'''
int main(void) {
 crypto=LoadLibraryA("C:\\Program Files\\Git\\mingw64\\bin\\libcrypto-3-x64.dll"); if(!crypto) abort();
 UCHAR payload[60]; for(UINT i=0;i<60;i++) payload[i]=(UCHAR)(i+7);
 SOCK sock={0}; UDP_ACCEL a={0};a.UdpSock=&sock;a.YourCookie=0x01020304;a.Now=100000;a.LastRecvYourTick=90000;
 for(UINT i=0;i<128;i++) a.MyKey_V2[i]=(UCHAR)i;
 for(UINT i=0;i<20;i++) {a.MyKey[i]=(UCHAR)i;a.NextIv[i]=(UCHAR)(i+32);}
 for(UINT i=0;i<12;i++) a.NextIv_V2[i]=(UCHAR)(i+32);
 a.Version=2;UdpAccelSend(&a,payload,60,0,0,false);printhex("udp_v2",captured,captured_size);
 a.Version=1;UdpAccelSend(&a,payload,60,0,0,false);printhex("udp_v1",captured,captured_size);
 UCHAR init_key[20],key1[20],key2[20],keep_request[20],keep_response[20];BUF *b;
 for(UINT i=0;i<20;i++) init_key[i]=(UCHAR)i;
'''+derive+r'''
 printhex("rudp_server_key",key1,20);printhex("rudp_client_key",key2,20);printhex("rudp_keep_request",keep_request,20);printhex("rudp_keep_response",keep_response,20);
 RUDP_STACK r={0};r.Now=100000;r.Protocol=RUDP_PROTOCOL_DNS;
 HashSha1(r.SvcNameHash,"softether_vpn",StrLen("softether_vpn"));
 RUDP_SESSION se={0};Copy(se.Key_Send,key2,20);for(UINT i=0;i<20;i++) se.NextIv[i]=(UCHAR)(i+32);se.YourTick=90000;se.LastRecvCompleteSeqNo=3;
 RUDPSendSegmentNow(&r,&se,7,payload,60);printhex("rudp_segment",captured,captured_size);
 UDPPACKET p={payload,60,0x1234};dns_packet(&r,&p);r.ServerMode=true;dns_packet(&r,&p);
 return 0;
}
'''
compiler = shutil.which("clang") or shutil.which("cc")
if not compiler or os.name != "nt":
    raise SystemExit("This fixture harness requires Windows, clang and Git for Windows OpenSSL")
build = ROOT / "tools/.vectors-build"
build.mkdir(exist_ok=True)
c = build / "transport_vectors.c"
c.write_text(stub + "\n".join(pieces) + dns + main, encoding="utf-8")
exe = build / "transport_vectors.exe"
subprocess.run([compiler, "-O2", str(c), "-o", str(exe)], check=True)
output = subprocess.check_output([str(exe)], text=True)
dest = ROOT / "core-protocol/src/test/resources/transport-vectors.properties"
dest.write_text("# Executed extracted Stable C writers at ed17437af9719ac66acab30faa29e375d613c35f\n" + output, encoding="ascii")
print(f"Wrote {len(output.splitlines())} C-derived transport vectors")
