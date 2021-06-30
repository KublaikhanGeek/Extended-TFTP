/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common/tftpsubs.h"
#include "tftp_client.h"

/*
 * TFTP User Program -- Protocol Machines
 */

struct modes
{
    const char* m_name;
    const char* m_mode;
    int m_openflags;
};

static const struct modes modes[]
    = { { "netascii", "netascii", O_TEXT }, { "ascii", "netascii", O_TEXT }, { "octet", "octet", O_BINARY },
        { "binary", "octet", O_BINARY },    { "image", "octet", O_BINARY },  { 0, 0, 0 } };

#define MODE_OCTET    (&modes[2])
#define MODE_NETASCII (&modes[0])
#define MODE_DEFAULT  MODE_NETASCII

#define CHECK_CONNECTED(a)                            \
    do                                                \
    {                                                 \
        if (!(a))                                     \
        {                                             \
            printf("No target machine specified.\n"); \
            return -1;                                \
        }                                             \
    } while (0)

#define TIMEOUT   5 /* secs between rexmt's */
#define PORT_FROM 61000
#define PORT_TO   63000
#define PKTSIZE   SEGSIZE + 4
char ackbuf[PKTSIZE];
char cmdbuf[PKTSIZE];
int g_timeout;
int g_rexmtval;
int g_maxtimeout;
sigjmp_buf g_timeoutbuf;

struct tftpObj
{
    int socket;
    int blocksize;
    int rexmt;
    int timeout;
    int trace;
    int verbose;
    int connected;
    int literal;
    struct modes* mode;
    union sock_addr peeraddr;
    union sock_addr localaddr;
};

static void nak(struct tftpObj*, int, const char*);
static int makerequest(int, const char*, struct tftphdr*, const char*, int, int);
static void printstats(const char*, unsigned long);
static void startclock(void);
static void stopclock(void);
static void timer(int);
static void tpacket(const char*, struct tftphdr*, int);
static int send_cmd_reply(struct tftpObj* obj, char* send, int sendLen, char* reply, int* replyLen);
static int exe_cmd(void* obj, u_short opcode, const char* cmd, int cmdSize, char* msg, int* msgSize);

static int makerequest(int request, const char* name, struct tftphdr* tp, const char* mode, int blocksize, int tsize)
{
    char* cp;
    char str[32] = { 0 };

    tp->th_opcode = htons((u_short)request);
    cp            = (char*)&(tp->th_stuff);
    strcpy(cp, name);
    cp += strlen(name);
    *cp++ = '\0';
    strcpy(cp, mode);
    cp += strlen(mode);
    *cp++ = '\0';

    if (blocksize > 0)
    {
        strcpy(cp, "blksize");
        cp += strlen("blksize");
        *cp++ = '\0';

        sprintf(str, "%d", blocksize);
        strcpy(cp, str);
        cp += strlen(str);
        *cp++ = '\0';
    }

    if (strcmp(mode, "octet") == 0)
    {
        strcpy(cp, "tsize");
        cp += strlen("tsize");
        *cp++ = '\0';

        memset(str, 0, sizeof(str));
        sprintf(str, "%d", tsize);
        strcpy(cp, str);
        cp += strlen(str);
        *cp++ = '\0';
    }

    return (cp - (char*)tp);
}

static const char* const errmsgs[] = {
    "Undefined error code",                /* 0 - EUNDEF */
    "File not found",                      /* 1 - ENOTFOUND */
    "Access denied",                       /* 2 - EACCESS */
    "Disk full or allocation exceeded",    /* 3 - ENOSPACE */
    "Illegal TFTP operation",              /* 4 - EBADOP */
    "Unknown transfer ID",                 /* 5 - EBADID */
    "File already exists",                 /* 6 - EEXISTS */
    "No such user",                        /* 7 - ENOUSER */
    "Failure to negotiate RFC2347 options" /* 8 - EOPTNEG */
};

#define ERR_CNT (sizeof(errmsgs) / sizeof(const char*))

/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 */
static void nak(struct tftpObj* tftp, int error, const char* msg)
{
    struct tftphdr* tp;
    int length;

    tp            = (struct tftphdr*)ackbuf;
    tp->th_opcode = htons((u_short)ERROR);
    tp->th_code   = htons((u_short)error);

    if (error >= 100)
    {
        /* This is a Unix errno+100 */
        if (!msg)
            msg = strerror(error - 100);
        error = EUNDEF;
    }
    else
    {
        if ((unsigned)error >= ERR_CNT)
            error = EUNDEF;

        if (!msg)
            msg = errmsgs[error];
    }

    tp->th_code = htons((u_short)error);

    length = strlen(msg) + 1;
    memcpy(tp->th_msg, msg, length);
    length += 4; /* Add space for header */

    if (tftp->trace)
        tpacket("sent", tp, length);
    if (sendto(tftp->socket, ackbuf, length, 0, &tftp->peeraddr.sa, SOCKLEN(&tftp->peeraddr)) != length)
        perror("nak");
}

static void tpacket(const char* s, struct tftphdr* tp, int n)
{
    static const char* opcodes[] = { "#0",   "RRQ",  "WRQ", "DATA", "ACK", "ERROR", "OACK", "DELE",  "CWD",
                                     "LIST", "NOOP", "MKD", "RMD",  "PWD", "CDUP",  "SIZE", "CHMOD", "RETURN" };
    char *cp, *file, *cmd;
    u_short op = ntohs((u_short)tp->th_opcode);

    if (op < RRQ || op > RETURN)
        printf("%s opcode=%x ", s, op);
    else
        printf("%s %s ", s, opcodes[op]);
    switch (op)
    {

    case RRQ:
    case WRQ:
        n -= 2;
        file = cp = (char*)&(tp->th_stuff);
        cp        = strchr(cp, '\0');
        printf("<file=%s, mode=%s>\n", file, cp + 1);
        break;

    case DATA:
        printf("<block=%d, %d bytes>\n", ntohs(tp->th_block), n - 4);
        break;

    case ACK:
        printf("<block=%d>\n", ntohs(tp->th_block));
        break;

    case OACK:
        printf("\n");
        break;

    case ERROR:
        printf("<code=%d, msg=%s>\n", ntohs(tp->th_code), tp->th_msg);
        break;

    case DELE:
    case CWD:
    case LIST:
    case MKD:
    case RMD:
    case SIZE:
        cmd = (char*)&(tp->th_stuff);
        printf("<cmd=%s>\n", cmd);
        break;

    case RETURN:
        printf("<code=%d, msg=%s>\n", ntohs(tp->th_code), tp->th_msg);
        break;
    }
}

struct timeval tstart;
struct timeval tstop;

static void startclock(void)
{
    (void)gettimeofday(&tstart, NULL);
}

static void stopclock(void)
{

    (void)gettimeofday(&tstop, NULL);
}

static void printstats(const char* direction, unsigned long amount)
{
    double delta;

    delta = (tstop.tv_sec + (tstop.tv_usec / 100000.0)) - (tstart.tv_sec + (tstart.tv_usec / 100000.0));
    printf("%s %lu bytes in %.1f seconds", direction, amount, delta);
    printf(" [%.0f bit/s]", (amount * 8.) / delta);
    putchar('\n');
}

static void timer(int sig)
{
    int save_errno = errno;

    (void)sig; /* Shut up unused warning */

    g_timeout += g_rexmtval;
    if (g_timeout >= g_maxtimeout)
    {
        printf("Transfer timed out.\n");
    }
    errno = save_errno;
    siglongjmp(g_timeoutbuf, 1);
}

// obj
void* tftp_create(const char* serverip, int port, const char* localip, int localport)
{
    struct tftpObj* obj;
    obj = (struct tftpObj*)malloc(sizeof(struct tftpObj));
    if (!obj)
    {
        printf("Failed to malloc \n");
        return NULL;
    }

    obj->mode  = MODE_DEFAULT;
    obj->rexmt = g_rexmtval = TIMEOUT;
    obj->timeout = g_maxtimeout = 5 * TIMEOUT;
    obj->blocksize              = 0;
    obj->trace                  = 0;
    obj->verbose                = 0;
    obj->connected              = 0;
    obj->literal                = 0;
    obj->socket                 = socket(AF_INET, SOCK_DGRAM, 0);
    if (obj->socket < 0)
    {
        printf("Failed to create socket \n");
        free(obj);
        return NULL;
    }

    bzero(&(obj->peeraddr), sizeof(obj->peeraddr));
    bzero(&(obj->localaddr), sizeof(obj->localaddr));

    if (serverip != NULL)
    {
        obj->connected                   = 1;
        obj->peeraddr.si.sin_family      = AF_INET;
        obj->peeraddr.si.sin_addr.s_addr = inet_addr(serverip);
        obj->peeraddr.si.sin_port        = htons(port);
    }
    else
    {
        printf("server ip is NULL\n");
    }

    obj->localaddr.si.sin_family = AF_INET;
    if (localip != NULL)
    {
        obj->localaddr.si.sin_addr.s_addr = inet_addr(localip);
    }

    if (localport != -1)
    {
        obj->localaddr.si.sin_port = htons(localport);
        if (bind(obj->socket, &obj->localaddr.sa, SOCKLEN(&obj->localaddr)) < 0)
        {
            printf("Failed bind port");
            free(obj);
            return NULL;
        }
    }
    else
    {
        if (pick_port_bind(obj->socket, &obj->localaddr, PORT_FROM, PORT_TO) < 0)
        {
            printf("Failed bind port");
            free(obj);
            return NULL;
        }
    }

    return obj;
}

void tftp_destroy(void* obj)
{
    if (obj != NULL)
    {
        free(obj);
    }
}

// setting
int tftp_set_server(void* obj, const char* serverip, int port)
{
    struct tftpObj* tftp;
    if (!obj || !serverip)
    {
        return -1;
    }

    tftp                              = (struct tftpObj*)obj;
    tftp->connected                   = 1;
    tftp->peeraddr.si.sin_family      = AF_INET;
    tftp->peeraddr.si.sin_addr.s_addr = inet_addr(serverip);
    tftp->peeraddr.si.sin_port        = htons(port);

    return 0;
}
int tftp_set_mode(void* obj, const char* mode)
{
    int ret = 0;
    const struct modes* p;
    struct tftpObj* tftp;
    if (!obj)
    {
        return -1;
    }

    tftp = (struct tftpObj*)obj;

    for (p = modes; p->m_name; p++)
    {
        if (!strcmp(mode, p->m_name))
            break;
    }

    if (p->m_name)
    {
        tftp->mode = p;
    }
    else
    {
        ret = -1;
        printf("invalid mode: %s\n", mode);
    }

    return ret;
}

int tftp_set_verbose(void* obj, int onoff)
{
    struct tftpObj* tftp;
    if (!obj)
    {
        return -1;
    }

    tftp          = (struct tftpObj*)obj;
    tftp->verbose = onoff;

    return 0;
}

int tftp_set_trace(void* obj, int onoff)
{
    struct tftpObj* tftp;
    if (!obj)
    {
        return -1;
    }

    tftp        = (struct tftpObj*)obj;
    tftp->trace = onoff;

    return 0;
}

int tftp_set_literal(void* obj, int onoff)
{
    struct tftpObj* tftp;
    if (!obj)
    {
        return -1;
    }

    tftp          = (struct tftpObj*)obj;
    tftp->literal = onoff;

    return 0;
}

int tftp_set_rexmt(void* obj, int rexmt)
{
    struct tftpObj* tftp;
    if (!obj || rexmt < 0)
    {
        return -1;
    }

    tftp        = (struct tftpObj*)obj;
    tftp->rexmt = g_rexmtval = rexmt;

    return 0;
}

int tftp_set_timeout(void* obj, int timeout)
{
    struct tftpObj* tftp;
    if (!obj || timeout < 0)
    {
        return -1;
    }

    tftp          = (struct tftpObj*)obj;
    tftp->timeout = g_maxtimeout = timeout;

    return 0;
}

int tftp_set_blocksize(void* obj, int blocksize)
{
    struct tftpObj* tftp;
    if (!obj)
    {
        return -1;
    }

    if (blocksize < 0 || blocksize > MAX_SEGSIZE)
    {
        return -1;
    }

    tftp            = (struct tftpObj*)obj;
    tftp->blocksize = blocksize;

    return 0;
}

int send_cmd_reply(struct tftpObj* obj, char* send, int sendLen, char* reply, int* replyLen)
{
    int n = 0;
    union sock_addr from;
    socklen_t fromlen;
    struct tftphdr* ap;
    if (!obj)
    {
        return -1;
    }

    ap        = (struct tftphdr*)reply;
    g_timeout = 0;
    (void)sigsetjmp(g_timeoutbuf, 1);
    if (g_timeout >= g_maxtimeout)
    {
        return -1;
    }

    if (sendto(obj->socket, send, sendLen, 0, &obj->peeraddr.sa, SOCKLEN(&obj->peeraddr)) != sendLen)
    {
        printf("tftp:sendto error\n");
        return -1;
    }

    // waiting for reply
    alarm(obj->rexmt);
    do
    {
        fromlen = sizeof(from);
        n       = recvfrom(obj->socket, reply, PKTSIZE, 0, &from.sa, &fromlen);
    } while (n <= 0);
    alarm(0);

    if (n < 0)
    {
        printf("tftp: recvfrom [cd] \n");
        return -1;
    }
    else
    {
        *replyLen = n;
        if (obj->trace)
            tpacket("received", ap, n);
    }

    return 0;
}

// cmd format
// +---------+------+---+------+---+------+---+------+---+------+---+
// |  opcode | arg1 | 0 | arg2 | 0 | arg3 | 0 | arg4 | 0 | argN | 0 |
// +---------+------+---+------+---+------+---+------+---+------+---+
// return format
// +---------+-------------+------+---+------+---+------+---+------+---+
// |  RETURN | return code | msg1 | 0 | msg2 | 0 | msg3 | 0 | msgN | 0 |
// +---------+-------------+------+---+------+---+------+---+------+---+
int exe_cmd(void* obj, u_short opcode, const char* cmd, int cmdSize, char* msg, int* msgSize)
{
    char* stuff;
    struct tftphdr* cp;
    struct tftphdr* ap;
    struct tftpObj* tftp;
    int size      = 0;
    int ret       = 0;
    int n         = 0;
    int ap_opcode = 0;
    int ap_code   = 0;
    if (obj == NULL)
    {
        printf("obj is NULL\n");
        return -1;
    }

    startclock();
    bsd_signal(SIGALRM, timer);

    memset(cmdbuf, 0, sizeof(cmdbuf));
    memset(ackbuf, 0, sizeof(ackbuf));

    tftp          = (struct tftpObj*)obj;
    cp            = (struct tftphdr*)cmdbuf;
    ap            = (struct tftphdr*)ackbuf;
    stuff         = (char*)&(cp->th_stuff);
    cp->th_opcode = htons(opcode);
    size          = sizeof(cp->th_opcode);
    CHECK_CONNECTED(tftp->connected);

    if (cmd)
    {
        memcpy(stuff, cmd, cmdSize);
        size = cmdSize + sizeof(cp->th_opcode);
        printf("cmd size: %d\n", size);
    }

    if (send_cmd_reply(tftp, cmdbuf, size, ackbuf, &n) < 0)
    {
        stopclock();
        return -1;
    }

    ap_opcode = ntohs((u_short)ap->th_opcode);
    ap_code   = ntohs((u_short)ap->th_code);
    if (ap_opcode == RETURN)
    {
        printf("Return code %d: %s\n", ap_code, ap->th_msg);
        memcpy(msg, ap->th_msg, n - 4); // 4 for return head
        *msgSize = n - 4;
        ret      = ap_code;
    }
    stopclock();

    return ret;
}

// cmd
int tftp_cmd_put(void* obj, const char* local, const char* remote, int* localsize, int* transfersize)
{
    struct tftphdr* ap; /* data and ack packets */
    struct tftphdr* dp;
    int n;
    volatile int is_request;
    volatile u_short block;
    volatile int size, convert;
    volatile off_t amount;
    union sock_addr from;
    socklen_t fromlen;
    FILE* file;
    u_short ap_opcode, ap_block;
    struct tftpObj* tftp;
    volatile int ret = 0;
    union sock_addr peeraddr;
    volatile int tsize = 0;

    if (!obj || !local || !remote || !localsize || !transfersize)
    {
        return -1;
    }

    startclock(); /* start stat's clock */
    tftp       = (struct tftpObj*)obj;
    dp         = r_init(); /* reset fillbuf/read-ahead code */
    ap         = (struct tftphdr*)ackbuf;
    convert    = !strcmp(tftp->mode->m_mode, "netascii");
    block      = 0;
    is_request = 1; /* First packet is the actual WRQ */
    amount     = 0;

    CHECK_CONNECTED(tftp->connected);
    file = fopen(local, convert ? "rt" : "rb");
    if (!file)
    {
        printf("Failed to open file: %s \n", local);
        return -1;
    }
    memcpy(&peeraddr, &tftp->peeraddr, sizeof(union sock_addr));

    bsd_signal(SIGALRM, timer);
    do
    {
        if (is_request)
        {
            struct stat stbuf;
            if (stat(local, &stbuf) < 0)
            {
                printf("Failed to read file %s size \n", local);
            }
            else
            {
                tsize = stbuf.st_size;
            }
            *localsize = tsize;
            if (tftp->blocksize > 0)
            {
                segsize = tftp->blocksize;
            }
            size = makerequest(WRQ, remote, dp, tftp->mode->m_mode, tftp->blocksize, tsize) - 4;
        }
        else
        {
            size = readit(file, &dp, convert);
            if (size < 0)
            {
                nak(tftp, errno + 100, NULL);
                break;
            }
            dp->th_opcode = htons((u_short)DATA);
            dp->th_block  = htons((u_short)block);
        }
        g_timeout = 0;
        (void)sigsetjmp(g_timeoutbuf, 1);
        if (g_timeout >= g_maxtimeout)
        {
            ret = -1;
            goto abort;
        }

        if (tftp->trace)
            tpacket("sent", dp, size + 4);
        n = sendto(tftp->socket, dp, size + 4, 0, &peeraddr.sa, SOCKLEN(&peeraddr));
        if (n != size + 4)
        {
            perror("tftp: sendto");
            ret = -1;
            goto abort;
        }
        read_ahead(file, convert);
        for (;;)
        {
            alarm(tftp->rexmt);
            do
            {
                fromlen = sizeof(from);
                n       = recvfrom(tftp->socket, ackbuf, sizeof(ackbuf), 0, &from.sa, &fromlen);
            } while (n <= 0);
            alarm(0);
            if (n < 0)
            {
                perror("tftp: recvfrom");
                ret = -1;
                goto abort;
            }
            sa_set_port(&peeraddr, SOCKPORT(&from)); /* added */
            if (tftp->trace)
                tpacket("received", ap, n);
            /* should verify packet came from server */
            ap_opcode = ntohs((u_short)ap->th_opcode);
            ap_block  = ntohs((u_short)ap->th_block);
            if (ap_opcode == ERROR)
            {
                printf("Error code %d: %s\n", ap_block, ap->th_msg);
                ret = -1;
                goto abort;
            }

            if (ap_opcode == OACK)
            {
                int argn  = 0;
                char* tmp = (char*)&(ap->th_stuff);
                char* end = (char*)ap + n;
                char* val;
                char* opt = tmp;

                while (tmp < end && *tmp)
                {
                    do
                    {
                        tmp++;
                    } while (tmp < end && *tmp);

                    if (*tmp)
                    {
                        printf("Request not null-terminated \n");
                        break;
                    }
                    argn++;

                    if (argn & 1)
                    {
                        val = ++tmp;
                        if (!strcmp(opt, "blksize"))
                        {
                            tftp->blocksize = atoi(val);
                            segsize         = tftp->blocksize;
                        }
                        else if (!strcmp(opt, "tsize"))
                        {
                            tsize = atoi(val);
                        }
                    }
                    else
                    {
                        opt = ++tmp;
                    }
                }
                printf("blksize:%d, size:%d\n", segsize, tsize);
                break;
            }
            if (ap_opcode == ACK)
            {
                int j;

                if (ap_block == block)
                {
                    break;
                }
                /* On an error, try to synchronize
                 * both sides.
                 */
                j = synchnet(tftp->socket);
                if (j && tftp->trace)
                {
                    printf("discarded %d packets\n", j);
                }
                /*
                 * RFC1129/RFC1350: We MUST NOT re-send the DATA
                 * packet in response to an invalid ACK.  Doing so
                 * would cause the Sorcerer's Apprentice bug.
                 */
            }
        }
        if (!is_request)
            amount += size;
        is_request = 0;
        block++;
        *transfersize = amount;
    } while (size == segsize || block == 1);
abort:
    fclose(file);
    stopclock();
    if (amount > 0 && tftp->verbose)
        printstats("Sent", amount);

    return ret;
}

int tftp_cmd_get(void* obj, const char* local, const char* remote, int* remotesize, int* transfersize)
{
    struct tftphdr* ap;
    struct tftphdr* dp;
    int n;
    volatile u_short block;
    volatile int size, firsttrip;
    volatile unsigned long amount;
    union sock_addr from;
    socklen_t fromlen;
    FILE* file;
    volatile int convert; /* true if converting crlf -> lf */
    u_short dp_opcode, dp_block;
    struct tftpObj* tftp;
    volatile int ret   = 0;
    volatile int tsize = 0;
    union sock_addr peeraddr;

    if (!obj || !local || !remote || !remotesize || !transfersize)
    {
        return -1;
    }

    startclock();
    tftp      = (struct tftpObj*)obj;
    dp        = w_init();
    ap        = (struct tftphdr*)ackbuf;
    convert   = !strcmp(tftp->mode->m_mode, "netascii");
    block     = 1;
    firsttrip = 1;
    amount    = 0;

    CHECK_CONNECTED(tftp->connected);
    file = fopen(local, convert ? "wt" : "wb");
    if (!file)
    {
        printf("Failed to open file: %s\n", local);
        return -1;
    }
    memcpy(&peeraddr, &tftp->peeraddr, sizeof(union sock_addr));

    bsd_signal(SIGALRM, timer);
    do
    {
        if (firsttrip)
        {
            if (tftp->blocksize > 0)
            {
                segsize = tftp->blocksize;
            }
            size      = makerequest(RRQ, remote, ap, tftp->mode->m_mode, tftp->blocksize, 0);
            firsttrip = 0;
        }
        else
        {
            ap->th_opcode = htons((u_short)ACK);
            ap->th_block  = htons((u_short)block);
            size          = 4;
            block++;
        }
        g_timeout = 0;
        (void)sigsetjmp(g_timeoutbuf, 1);
        if (g_timeout >= g_maxtimeout)
        {
            fclose(file);
            stopclock();
            if (amount > 0 && tftp->verbose)
                printstats("Received", amount);
            return -1;
        }
    send_ack:
        if (tftp->trace)
            tpacket("sent", ap, size);
        if (sendto(tftp->socket, ackbuf, size, 0, &peeraddr.sa, SOCKLEN(&peeraddr)) != size)
        {
            alarm(0);
            perror("tftp: sendto");
            ret = -1;
            goto abort;
        }
        write_behind(file, convert);
        for (;;)
        {
            alarm(tftp->rexmt);
            do
            {
                fromlen = sizeof(from);
                n       = recvfrom(tftp->socket, dp, MAX_SEGSIZE + 4, 0, &from.sa, &fromlen);
            } while (n <= 0);
            alarm(0);
            if (n < 0)
            {
                perror("tftp: recvfrom");
                ret = -1;
                goto abort;
            }
            sa_set_port(&peeraddr, SOCKPORT(&from)); /* added */
            if (tftp->trace)
                tpacket("received", dp, n);
            /* should verify client address */
            dp_opcode = ntohs((u_short)dp->th_opcode);
            dp_block  = ntohs((u_short)dp->th_block);
            if (dp_opcode == ERROR)
            {
                printf("Error code %d: %s\n", dp_block, dp->th_msg);
                ret = -1;
                goto abort;
            }

            if (dp_opcode == OACK)
            {
                int argn  = 0;
                char* tmp = (char*)&(dp->th_stuff);
                char* end = (char*)dp + n;
                char* val;
                char* opt = tmp;

                while (tmp < end && *tmp)
                {
                    do
                    {
                        tmp++;
                    } while (tmp < end && *tmp);

                    if (*tmp)
                    {
                        break;
                    }
                    argn++;

                    if (argn & 1)
                    {
                        val = ++tmp;
                        if (!strcmp(opt, "blksize"))
                        {
                            tftp->blocksize = atoi(val);
                            segsize         = tftp->blocksize;
                        }
                        else if (!strcmp(opt, "tsize"))
                        {
                            tsize       = atoi(val);
                            *remotesize = tsize;
                        }
                    }
                    else
                    {
                        opt = ++tmp;
                    }
                }
                printf("blksize:%d, size:%d\n", segsize, tsize);

                ap->th_opcode = htons((u_short)ACK);
                ap->th_block  = htons(0);
                size          = 4;
                goto send_ack;
            }

            if (dp_opcode == DATA)
            {
                int j;

                if (dp_block == block)
                {
                    break; /* have next packet */
                }
                /* On an error, try to synchronize
                 * both sides.
                 */
                j = synchnet(tftp->socket);
                if (j && tftp->trace)
                {
                    printf("discarded %d packets\n", j);
                }
                if (dp_block == (block - 1))
                {
                    goto send_ack; /* resend ack */
                }
            }
        }
        /*      size = write(fd, dp->th_data, n - 4); */
        size = writeit(file, &dp, n - 4, convert);
        if (size < 0)
        {
            nak(tftp, errno + 100, NULL);
            break;
        }
        amount += size;
        *transfersize = amount;
    } while (size == segsize);
abort:                                   /* ok to ack, since user */
    ap->th_opcode = htons((u_short)ACK); /* has seen err msg */
    ap->th_block  = htons((u_short)block);
    (void)sendto(tftp->socket, ackbuf, 4, 0, (struct sockaddr*)&peeraddr, SOCKLEN(&peeraddr));
    write_behind(file, convert); /* flush last buffer */
    fclose(file);
    stopclock();
    if (amount > 0 && tftp->verbose)
        printstats("Received", amount);

    return ret;
}

int tftp_cmd_cd(void* obj, const char* path)
{
    int msgSize = 0;
    char msg[PKTSIZE];
    if (!obj || !path)
    {
        return -1;
    }

    memset(msg, 0, PKTSIZE);
    printf("cd path: %s\n", path);
    return exe_cmd(obj, CWD, path, strlen(path) + 1, msg, &msgSize);
}

int tftp_cmd_cdup(void* obj)
{
    int msgSize = 0;
    char path[8];
    char msg[PKTSIZE];
    if (!obj)
    {
        return -1;
    }
    strcpy(path, "..");
    memset(msg, 0, PKTSIZE);
    return exe_cmd(obj, CDUP, path, strlen(path) + 1, msg, &msgSize);
}

int tftp_cmd_lcd(void* obj, const char* path)
{
    if (!obj || !path)
    {
        return -1;
    }
    return 0;
}

int tftp_cmd_pwd(void* obj, char* pwd)
{
    int msgSize = 0;
    if (!obj || !pwd)
    {
        return -1;
    }
    return exe_cmd(obj, PWD, NULL, 0, pwd, &msgSize);
}

int tftp_cmd_delete(void* obj, const char* path)
{
    int msgSize = 0;
    char msg[PKTSIZE];
    if (!obj || !path)
    {
        return -1;
    }
    memset(msg, 0, PKTSIZE);
    return exe_cmd(obj, DELE, path, strlen(path) + 1, msg, &msgSize);
}

// int tftp_cmd_rename(void* obj, const char* src, const char* dst)
//{
//    char* cp;
//    char cmd[PKTSIZE];
//    char msg[PKTSIZE];
//    int msgSize = 0;
//    memset(cmd, 0, PKTSIZE);
//
//    cp = cmd;
//    strcpy(cp, src);
//    cp += strlen(src);
//    *cp++ = '\0';
//    strcpy(cp, dst);
//    cp += strlen(dst);
//    *cp++ = '\0';
//    return exe_cmd(obj, CHMOD, cmd, cp - cmd, msg, &msgSize);
//}

int tftp_cmd_ls(void* obj, char* buf)
{
    struct tftphdr* ap;
    struct tftphdr* dp;
    struct tftpObj* tftp;
    int n;
    volatile u_short block;
    volatile int size, firsttrip;
    volatile unsigned long amount;
    union sock_addr from;
    socklen_t fromlen;
    u_short dp_opcode, dp_block;
    volatile int ret = TFTP_LSOK;
    union sock_addr peeraddr;
    char* listBuf;
    if (!obj || !buf)
    {
        return -1;
    }

    startclock();
    tftp      = (struct tftpObj*)obj;
    ap        = (struct tftphdr*)ackbuf;
    dp        = (struct tftphdr*)cmdbuf;
    block     = 1;
    firsttrip = 1;
    amount    = 0;
    listBuf   = buf;

    CHECK_CONNECTED(tftp->connected);
    memcpy(&peeraddr, &tftp->peeraddr, sizeof(union sock_addr));

    memset(cmdbuf, 0, sizeof(cmdbuf));
    memset(ackbuf, 0, sizeof(ackbuf));

    bsd_signal(SIGALRM, timer);
    do
    {
        if (firsttrip)
        {
            ap->th_opcode = htons(LIST);
            size          = sizeof(ap->th_opcode);
            firsttrip     = 0;
        }
        else
        {
            ap->th_opcode = htons((u_short)ACK);
            ap->th_block  = htons((u_short)block);
            size          = 4;
            block++;
        }
        g_timeout = 0;
        (void)sigsetjmp(g_timeoutbuf, 1);
        if (g_timeout >= g_maxtimeout)
        {
            stopclock();
            return -1;
        }

    send_ack:
        if (tftp->trace)
            tpacket("sent", ap, size);
        if (sendto(tftp->socket, ackbuf, size, 0, &peeraddr.sa, SOCKLEN(&peeraddr)) != size)
        {
            alarm(0);
            perror("tftp: sendto");
            ret = -1;
            goto abort;
        }
        for (;;)
        {
            alarm(tftp->rexmt);
            do
            {
                fromlen = sizeof(from);
                n       = recvfrom(tftp->socket, dp, PKTSIZE, 0, &from.sa, &fromlen);
            } while (n <= 0);
            alarm(0);
            if (n < 0)
            {
                perror("tftp: recvfrom");
                ret = -1;
                goto abort;
            }
            sa_set_port(&peeraddr, SOCKPORT(&from)); /* added */
            if (tftp->trace)
                tpacket("received", dp, n);
            /* should verify client address */
            dp_opcode = ntohs((u_short)dp->th_opcode);
            dp_block  = ntohs((u_short)dp->th_block);
            if (dp_opcode == ERROR)
            {
                printf("Error code %d: %s\n", dp_block, dp->th_msg);
                ret = -1;
                goto abort;
            }
            if (dp_opcode == DATA)
            {
                int j;

                if (dp_block == block)
                {
                    break; /* have next packet */
                }
                /* On an error, try to synchronize
                 * both sides.
                 */
                j = synchnet(tftp->socket);
                if (j && tftp->trace)
                {
                    printf("discarded %d packets\n", j);
                }
                if (dp_block == (block - 1))
                {
                    goto send_ack; /* resend ack */
                }
            }
        }

        size = n - 4;
        memcpy(listBuf, dp->th_data, size);
        listBuf += size;
        amount += size;
    } while (size == segsize);
abort:                                   /* ok to ack, since user */
    ap->th_opcode = htons((u_short)ACK); /* has seen err msg */
    ap->th_block  = htons((u_short)block);
    (void)sendto(tftp->socket, ackbuf, 4, 0, (struct sockaddr*)&tftp->peeraddr, SOCKLEN(&tftp->peeraddr));
    stopclock();
    if (amount > 0 && tftp->verbose)
        printstats("Received", amount);

    return ret;
}

int tftp_cmd_dir(void* obj, char* buf)
{
    if (!obj || !buf)
    {
        return -1;
    }
    return tftp_cmd_ls(obj, buf);
}

int tftp_cmd_mkdir(void* obj, const char* path)
{
    int msgSize = 0;
    char msg[PKTSIZE];
    if (!obj || !path)
    {
        return -1;
    }
    memset(msg, 0, PKTSIZE);
    return exe_cmd(obj, MKD, path, strlen(path) + 1, msg, &msgSize);
}

int tftp_cmd_rmdir(void* obj, const char* path)
{
    int msgSize = 0;
    char msg[PKTSIZE];
    if (!obj || !path)
    {
        return -1;
    }
    memset(msg, 0, PKTSIZE);
    return exe_cmd(obj, RMD, path, strlen(path) + 1, msg, &msgSize);
}

int tftp_cmd_size(void* obj, const char* path, int* size)
{
    int ret     = 0;
    int msgSize = 0;
    char msg[PKTSIZE];
    if (!obj || !path || !size)
    {
        return -1;
    }

    memset(msg, 0, PKTSIZE);
    ret = exe_cmd(obj, SIZE, path, strlen(path) + 1, msg, &msgSize);
    if (ret == TFTP_SIZEOK)
    {
        *size = atoi(msg);
    }

    return ret;
}

int tftp_cmd_chmod(void* obj, const char* path, const char* mode)
{
    char* cp;
    char cmd[PKTSIZE];
    char msg[PKTSIZE];
    int msgSize = 0;
    if (!obj || !path || !mode)
    {
        return -1;
    }
    memset(cmd, 0, PKTSIZE);

    cp = cmd;
    strcpy(cp, path);
    cp += strlen(path);
    *cp++ = '\0';
    strcpy(cp, mode);
    cp += strlen(mode);
    *cp++ = '\0';
    return exe_cmd(obj, CHMOD, cmd, cp - cmd, msg, &msgSize);
}
