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

/* Many bug fixes are from Jim Guyton <guyton@rand-unix> */

/*
 * TFTP User Program -- Command Interface.
 */
#include <sys/file.h>
#include <ctype.h>
#ifdef WITH_READLINE
#include <readline/readline.h>
#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif
#endif

#include "tftp_client.h"

#define LBUFLEN  200 /* size of input buffer */
#define REXMTVAL 5

int f = -1;
u_short port;
int literal;
#ifdef WITH_READLINE
char* line = NULL;
#else
char line[LBUFLEN];
#endif
int margc;
char* margv[20];
const char* prompt = "tftp> ";
sigjmp_buf toplevel;
void intr(int);
struct servent* sp;
int portrange               = 0;
unsigned int portrange_from = 0;
unsigned int portrange_to   = 0;
union sock_addr peeraddr;
int trace;
int literal;
int verbose;
int connected;
char mode[64];
void* tftp;

void get(int, char**);
void help(int, char**);
void modecmd(int, char**);
void put(int, char**);
void quit(int, char**);
void setascii(int, char**);
void setbinary(int, char**);
void setpeer(int, char**);
void setrexmt(int, char**);
void settimeout(int, char**);
void settrace(int, char**);
void setverbose(int, char**);
void status(int, char**);
void setliteral(int, char**);
void do_cd(int, char**);
void do_cdup(int, char**);
void do_lcd(int, char**);
void do_pwd(int, char**);
void do_delete(int, char**);
void do_mdelete(int, char**);
void do_rename(int, char**);
void do_ls(int, char**);
void do_dir(int, char**);
void do_mkdir(int, char**);
void do_rmdir(int, char**);
void do_mget(int, char**);
void do_mput(int, char**);
void do_size(int, char**);
void do_chmod(int, char**);
void do_md5(int, char**);

static void command(void);
static void getusage(char*);
static void makeargv(void);
static void putusage(char*);

#define HELPINDENT (sizeof("connect"))

struct cmd
{
    const char* name;
    const char* help;
    void (*handler)(int, char**);
};

struct cmd cmdtab[] = { { "connect", "connect to remote tftp", setpeer },
                        { "mode", "set file transfer mode", modecmd },
                        { "put", "send file", put },
                        { "get", "receive file", get },
                        { "quit", "exit tftp", quit },
                        { "verbose", "toggle verbose mode", setverbose },
                        { "trace", "toggle packet tracing", settrace },
                        { "literal", "toggle literal mode, ignore ':' in file name", setliteral },
                        { "status", "show current status", status },
                        { "binary", "set mode to octet", setbinary },
                        { "ascii", "set mode to netascii", setascii },
                        { "rexmt", "set per-packet transmission timeout", setrexmt },
                        { "timeout", "set total retransmission timeout", settimeout },
                        { "?", "print help information", help },
                        { "help", "print help information", help },
                        { "cd", "change working directory", do_cd },
                        { "cdup", "change to parent directory", do_cdup },
                        { "lcd", "change working directory on the local machine", do_lcd },
                        { "pwd", "print working directory", do_pwd },
                        { "delete", "delete file", do_delete },
                        { "mdelete", "delete files", do_mdelete },
                        { "rename", "rename the file from on the remote machine", do_rename },
                        { "ls",
                          "returns information of a file or directory if specified, else information of the current "
                          "working directory is returned.",
                          do_ls },
                        { "dir",
                          "returns information of a file or directory if specified, else information of the current "
                          "working directory is returned.",
                          do_dir },
                        { "mkdir", "make directory", do_mkdir },
                        { "rmdir", "remove a directory", do_rmdir },
                        { "mget", "receive files", do_mget },
                        { "mput", "send files", do_mput },
                        { "size", "return the size of a file", do_size },
                        { "chmod", "changes the permissions of each given file according to mode", do_chmod },
                        { "md5", "return the md5 value of a file", do_md5 },
                        { 0, 0, 0 } };

struct cmd* getcmd(char*);
char* tail(char*);

char* xstrdup(const char*);

const char* program;

static void usage(int errcode)
{
    fprintf(stderr, "Usage: %s [-v][-l][-m mode] [host [port]] [-c command]\n", program);
    exit(errcode);
}

int main(int argc, char* argv[])
{
    union sock_addr sa;
    int arg;
    static int pargc, peerargc;
    static int iscmd = 0;
    char** pargv;
    const char* optx;
    char* peerargv[3];
    int ret = 0;

    program = argv[0];

    peerargv[0] = argv[0];
    peerargc    = 1;

    strcpy(mode, "netascii");
    tftp = tftp_create(NULL, -1, NULL, -1);
    if (!tftp)
    {
        perror("tftp: create failed");
        exit(EX_OSERR);
    }

    for (arg = 1; !iscmd && arg < argc; arg++)
    {
        if (argv[arg][0] == '-')
        {
            for (optx = &argv[arg][1]; *optx; optx++)
            {
                switch (*optx)
                {
                case 'v':
                    verbose = 1;
                    tftp_set_verbose(tftp, verbose);
                    break;
                case 'V':
                    /* Print version and configuration to stdout and exit */
                    printf("%s\n", TFTP_CONFIG_STR);
                    exit(0);
                case 'l':
                    literal = 1;
                    tftp_set_literal(tftp, literal);
                    break;
                case 'm':
                    if (++arg >= argc)
                        usage(EX_USAGE);
                    {
                        strcpy(mode, argv[arg]);
                        if (tftp_set_mode(tftp, argv[arg]) < 0)
                        {
                            fprintf(stderr, "%s: invalid mode: %s\n", argv[0], argv[arg]);
                            exit(EX_USAGE);
                        }
                    }
                    break;
                case 'c':
                    iscmd = 1;
                    break;
                case 'R':
                    if (++arg >= argc)
                        usage(EX_USAGE);
                    if (sscanf(argv[arg], "%u:%u", &portrange_from, &portrange_to) != 2 || portrange_from > portrange_to
                        || portrange_to > 65535)
                    {
                        fprintf(stderr, "Bad port range: %s\n", argv[arg]);
                        exit(EX_USAGE);
                    }
                    portrange = 1;
                    break;
                case 'h':
                default:
                    usage(*optx == 'h' ? 0 : EX_USAGE);
                }
            }
        }
        else
        {
            if (peerargc >= 3)
                usage(EX_USAGE);

            peerargv[peerargc++] = argv[arg];
        }
    }

    pargv = argv + arg;
    pargc = argc - arg;

    sp = getservbyname("tftp", "udp");
    if (sp == 0)
    {
        /* Use canned values */
        if (verbose)
            fprintf(stderr, "tftp: tftp/udp: unknown service, faking it...\n");
        sp            = xmalloc(sizeof(struct servent));
        sp->s_name    = (char*)"tftp";
        sp->s_aliases = NULL;
        sp->s_port    = htons(IPPORT_TFTP);
        sp->s_proto   = (char*)"udp";
    }

    bsd_signal(SIGINT, intr);

    if (peerargc)
    {
        /* Set peer */
        if (sigsetjmp(toplevel, 1) != 0)
            exit(EX_NOHOST);
        setpeer(peerargc, peerargv);
    }

    if (iscmd && pargc)
    {
        /* -c specified; execute command and exit */
        struct cmd* c;

        if (sigsetjmp(toplevel, 1) != 0)
            exit(EX_UNAVAILABLE);

        c = getcmd(pargv[0]);
        if (c == (struct cmd*)-1 || c == (struct cmd*)0)
        {
            fprintf(stderr, "%s: invalid command: %s\n", argv[0], pargv[1]);
            exit(EX_USAGE);
        }
        (*c->handler)(pargc, pargv);
        exit(0);
    }
#ifdef WITH_READLINE
#ifdef HAVE_READLINE_HISTORY_H
    using_history();
#endif
#endif

    if (sigsetjmp(toplevel, 1) != 0)
        (void)putchar('\n');
    command();

    return 0; /* Never reached */
}

char* hostname;

/* Called when a command is incomplete; modifies
   the global variable "line" */
static void getmoreargs(const char* partial, const char* mprompt)
{
#ifdef WITH_READLINE
    char* eline;
    int len, elen;

    len   = strlen(partial);
    eline = readline(mprompt);
    if (!eline)
        exit(0); /* EOF */

    elen = strlen(eline);

    if (line)
    {
        free(line);
        line = NULL;
    }
    line = xmalloc(len + elen + 1);
    strcpy(line, partial);
    strcpy(line + len, eline);
    free(eline);

#ifdef HAVE_READLINE_HISTORY_H
    add_history(line);
#endif
#else
    int len = strlen(partial);

    strcpy(line, partial);
    fputs(mprompt, stdout);
    if (fgets(line + len, LBUFLEN - len, stdin) == 0)
        if (feof(stdin))
            exit(0); /* EOF */
#endif
}

void setpeer(int argc, char* argv[])
{
    int err;

    if (argc < 2)
    {
        getmoreargs("connect ", "(to) ");
        makeargv();
        argc = margc;
        argv = margv;
    }
    if ((argc < 2) || (argc > 3))
    {
        printf("usage: %s host-name [port]\n", argv[0]);
        return;
    }

    peeraddr.sa.sa_family = AF_INET;
    err                   = set_sock_addr(argv[1], &peeraddr, &hostname);
    if (err)
    {
        printf("Error: %s\n", gai_strerror(err));
        printf("%s: unknown host\n", argv[1]);
        connected = 0;
        return;
    }
    port = sp->s_port;
    if (argc == 3)
    {
        struct servent* usp;
        usp = getservbyname(argv[2], "udp");
        if (usp)
        {
            port = usp->s_port;
        }
        else
        {
            unsigned long myport;
            char* ep;
            myport = strtoul(argv[2], &ep, 10);
            if (*ep || myport > 65535UL)
            {
                printf("%s: bad port number\n", argv[2]);
                connected = 0;
                return;
            }
            port = htons((u_short)myport);
        }
    }

    char tmp[INET6_ADDRSTRLEN], *tp;
    tp = (char*)inet_ntop(peeraddr.sa.sa_family, SOCKADDR_P(&peeraddr), tmp, INET6_ADDRSTRLEN);
    if (!tp)
    {
        tp = (char*)"???";
        printf("Connected error %s (%s), port %u\n", hostname, tp, (unsigned int)ntohs(port));
        return;
    }
    if (verbose)
        printf("Connected to %s (%s), port %u\n", hostname, tp, (unsigned int)ntohs(port));

    tftp_set_server(tftp, tp, port);
    connected = 1;
}

void modecmd(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Using netascii mode to transfer files.\n");
        return;
    }

    if (argc == 2)
    {
        if (tftp_set_mode(tftp, argv[1]) < 0)
        {
            printf("%s: unknown mode\n", argv[1]);
        }
    }
    return;
}

void setbinary(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */
    tftp_set_mode(tftp, "octet");
}

void setascii(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */
    tftp_set_mode(tftp, "netascii");
}

/*
 * Send file(s).
 */
void put(int argc, char* argv[])
{
    int fd;
    int n, err;
    char *cp, *targ;
    char tmp[INET6_ADDRSTRLEN], *tp;

    if (argc < 2)
    {
        getmoreargs("send ", "(file) ");
        makeargv();
        argc = margc;
        argv = margv;
    }
    if (argc < 2)
    {
        putusage(argv[0]);
        return;
    }
    targ = argv[argc - 1];
    if (!literal && strchr(argv[argc - 1], ':'))
    {
        for (n = 1; n < argc - 1; n++)
            if (strchr(argv[n], ':'))
            {
                putusage(argv[0]);
                return;
            }
        cp                    = argv[argc - 1];
        targ                  = strchr(cp, ':');
        *targ++               = 0;
        peeraddr.sa.sa_family = AF_INET;
        err                   = set_sock_addr(cp, &peeraddr, &hostname);
        if (err)
        {
            printf("Error: %s\n", gai_strerror(err));
            printf("%s: unknown host\n", argv[1]);
            connected = 0;
            return;
        }
        tp = (char*)inet_ntop(peeraddr.sa.sa_family, SOCKADDR_P(&peeraddr), tmp, INET6_ADDRSTRLEN);
        if (!tp)
        {
            printf("%s: unknown host\n", argv[1]);
            return;
        }
        tftp_set_server(tftp, tp, port);
        connected = 1;
    }
    if (!connected)
    {
        printf("No target machine specified.\n");
        return;
    }
    if (argc < 4)
    {
        cp = argc == 2 ? tail(targ) : argv[1];
        if (verbose)
            printf("putting %s to %s:%s [%s]\n", cp, hostname, targ, mode);
        tftp_cmd_put(tftp, cp, targ);
        return;
    }
    /* this assumes the target is a directory */
    /* on a remote unix system.  hmmmm.  */
    cp    = strchr(targ, '\0');
    *cp++ = '/';
    for (n = 1; n < argc - 1; n++)
    {
        strcpy(cp, tail(argv[n]));
        if (verbose)
            printf("putting %s to %s:%s [%s]\n", argv[n], hostname, targ, mode);
        tftp_cmd_put(tftp, cp, targ);
    }
}

static void putusage(char* s)
{
    printf("usage: %s file ... host:target, or\n", s);
    printf("       %s file ... target (when already connected)\n", s);
}

/*
 * Receive file(s).
 */
void get(int argc, char* argv[])
{
    int fd;
    int n;
    char* cp;
    char* src;
    char tmp[INET6_ADDRSTRLEN], *tp;

    if (argc < 2)
    {
        getmoreargs("get ", "(files) ");
        makeargv();
        argc = margc;
        argv = margv;
    }
    if (argc < 2)
    {
        getusage(argv[0]);
        return;
    }
    if (!connected)
    {
        for (n = 1; n < argc; n++)
            if (literal || strchr(argv[n], ':') == 0)
            {
                getusage(argv[0]);
                return;
            }
    }
    for (n = 1; n < argc; n++)
    {
        src = strchr(argv[n], ':');
        if (literal || src == NULL)
            src = argv[n];
        else
        {
            int err;

            *src++                = 0;
            peeraddr.sa.sa_family = AF_INET;
            err                   = set_sock_addr(argv[n], &peeraddr, &hostname);
            if (err)
            {
                printf("Warning: %s\n", gai_strerror(err));
                printf("%s: unknown host\n", argv[1]);
                continue;
            }
            tp = (char*)inet_ntop(peeraddr.sa.sa_family, SOCKADDR_P(&peeraddr), tmp, INET6_ADDRSTRLEN);
            if (!tp)
            {
                printf("%s: unknown host\n", argv[1]);
                return;
            }
            tftp_set_server(tftp, tp, port);
            connected = 1;
        }
        if (argc < 4)
        {
            cp = argc == 3 ? argv[2] : tail(src);
            if (verbose)
                printf("getting from %s:%s to %s [%s]\n", hostname, src, cp, mode);
            tftp_cmd_get(tftp, cp, src);
            break;
        }
        cp = tail(src); /* new .. jdg */
        if (verbose)
            printf("getting from %s:%s to %s [%s]\n", hostname, src, cp, mode);
        tftp_cmd_get(tftp, cp, src);
    }
}

static void getusage(char* s)
{
    printf("usage: %s host:file host:file ... file, or\n", s);
    printf("       %s file file ... file if connected\n", s);
}

int rexmtval = REXMTVAL;
void setrexmt(int argc, char* argv[])
{
    int t;

    if (argc < 2)
    {
        getmoreargs("rexmt-timeout ", "(value) ");
        makeargv();
        argc = margc;
        argv = margv;
    }
    if (argc != 2)
    {
        printf("usage: %s value\n", argv[0]);
        return;
    }
    t = atoi(argv[1]);
    if (t < 0)
    {
        printf("%s: bad value\n", argv[1]);
    }
    else
    {
        rexmtval = t;
        tftp_set_rexmt(tftp, t);
    }
}

int maxtimeout = 5 * REXMTVAL;
void settimeout(int argc, char* argv[])
{
    int t;

    if (argc < 2)
    {
        getmoreargs("maximum-timeout ", "(value) ");
        makeargv();
        argc = margc;
        argv = margv;
    }
    if (argc != 2)
    {
        printf("usage: %s value\n", argv[0]);
        return;
    }
    t = atoi(argv[1]);
    if (t < 0)
    {
        printf("%s: bad value\n", argv[1]);
    }
    else
    {
        maxtimeout = t;
        tftp_set_timeout(tftp, t);
    }
}

void setliteral(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */
    tftp_set_literal(tftp, !literal);
    printf("Literal mode %s.\n", literal ? "on" : "off");
}

void status(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */
    if (connected)
        printf("Connected to %s.\n", hostname);
    else
        printf("Not connected.\n");
    printf("Mode: %s Verbose: %s Tracing: %s Literal: %s\n", mode, verbose ? "on" : "off", trace ? "on" : "off",
           literal ? "on" : "off");
    printf("Rexmt-interval: %d seconds, Max-timeout: %d seconds\n", rexmtval, maxtimeout);
}

void intr(int sig)
{
    (void)sig; /* Quiet unused warning */

    bsd_signal(SIGALRM, SIG_IGN);
    alarm(0);
    siglongjmp(toplevel, -1);
}

char* tail(char* filename)
{
    char* s;

    while (*filename)
    {
        s = strrchr(filename, '/');
        if (s == NULL)
            break;
        if (s[1])
            return (s + 1);
        *s = '\0';
    }
    return (filename);
}

/*
 * Command parser.
 */
static void command(void)
{
    struct cmd* c;

    for (;;)
    {
#ifdef WITH_READLINE
        if (line)
        {
            free(line);
            line = NULL;
        }
        line = readline(prompt);
        if (!line)
            exit(0); /* EOF */
#else
        fputs(prompt, stdout);
        if (fgets(line, LBUFLEN, stdin) == 0)
        {
            if (feof(stdin))
            {
                exit(0);
            }
            else
            {
                continue;
            }
        }
#endif
        if ((line[0] == 0) || (line[0] == '\n'))
            continue;
#ifdef WITH_READLINE
#ifdef HAVE_READLINE_HISTORY_H
        add_history(line);
#endif
#endif
        makeargv();
        if (margc == 0)
            continue;

        c = getcmd(margv[0]);
        if (c == (struct cmd*)-1)
        {
            printf("?Ambiguous command\n");
            continue;
        }
        if (c == 0)
        {
            printf("?Invalid command\n");
            continue;
        }
        (*c->handler)(margc, margv);
    }
}

struct cmd* getcmd(char* name)
{
    const char* p;
    char* q;
    struct cmd *c, *found;
    int nmatches, longest;

    longest  = 0;
    nmatches = 0;
    found    = 0;
    for (c = cmdtab; (p = c->name) != NULL; c++)
    {
        for (q = name; *q == *p++; q++)
            if (*q == 0) /* exact match? */
                return (c);
        if (!*q)
        { /* the name was a prefix */
            if (q - name > longest)
            {
                longest  = q - name;
                nmatches = 1;
                found    = c;
            }
            else if (q - name == longest)
                nmatches++;
        }
    }
    if (nmatches > 1)
        return ((struct cmd*)-1);
    return (found);
}

/*
 * Slice a string up into argc/argv.
 */
static void makeargv(void)
{
    char* cp;
    char** argp = margv;

    margc = 0;
    for (cp = line; *cp;)
    {
        while (isspace(*cp))
            cp++;
        if (*cp == '\0')
            break;
        *argp++ = cp;
        margc += 1;
        while (*cp != '\0' && !isspace(*cp))
            cp++;
        if (*cp == '\0')
            break;
        *cp++ = '\0';
    }
    *argp++ = 0;
}

void quit(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */
    exit(0);
}

/*
 * Help command.
 */
void help(int argc, char* argv[])
{
    struct cmd* c;

    printf("%s\n", VERSION);

    if (argc == 1)
    {
        printf("Commands may be abbreviated.  Commands are:\n\n");
        for (c = cmdtab; c->name; c++)
            printf("%-*s\t%s\n", (int)HELPINDENT, c->name, c->help);
        return;
    }
    while (--argc > 0)
    {
        char* arg;
        arg = *++argv;
        c   = getcmd(arg);
        if (c == (struct cmd*)-1)
            printf("?Ambiguous help command %s\n", arg);
        else if (c == (struct cmd*)0)
            printf("?Invalid help command %s\n", arg);
        else
            printf("%s\n", c->help);
    }
}

void settrace(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */

    tftp_set_trace(tftp, !trace);
    printf("Packet tracing %s.\n", trace ? "on" : "off");
}

void setverbose(int argc, char* argv[])
{
    (void)argc;
    (void)argv; /* Quiet unused warning */

    tftp_set_verbose(tftp, !verbose);
    printf("Verbose mode %s.\n", verbose ? "on" : "off");
}

void do_cd(int argc, char* argv[])
{
}
void do_cdup(int argc, char* argv[])
{
}
void do_lcd(int argc, char* argv[])
{
}
void do_pwd(int argc, char* argv[])
{
}
void do_delete(int argc, char* argv[])
{
}
void do_mdelete(int argc, char* argv[])
{
}
void do_rename(int argc, char* argv[])
{
}
void do_ls(int argc, char* argv[])
{
}
void do_dir(int argc, char* argv[])
{
}
void do_mkdir(int argc, char* argv[])
{
}
void do_rmdir(int argc, char* argv[])
{
}
void do_mget(int argc, char* argv[])
{
}
void do_mput(int argc, char* argv[])
{
}
void do_size(int argc, char* argv[])
{
}
void do_chmod(int argc, char* argv[])
{
}
void do_md5(int argc, char* argv[])
{
}