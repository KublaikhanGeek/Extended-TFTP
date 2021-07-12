/*
 * Copyright (c) 1983 Regents of the University of California.
 * Copyright (c) 1999-2009 H. Peter Anvin
 * Copyright (c) 2011-2014 Intel Corporation; author: H. Peter Anvin
 * All rights reserved.
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

#include "config.h" /* Must be included first */
#include "tftpd.h"

/*
 * Trivial file transfer protocol server.
 *
 * This version includes many modifications by Jim Guyton <guyton@rand-unix>
 */

#include <sys/ioctl.h>
#include <signal.h>
#include <ctype.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/param.h>
#include <dirent.h>

#include "common/tftpsubs.h"
#include "common/ikcp.h"
#include "recvfrom.h"
#include "remap.h"

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h> /* Necessary for FIONBIO on Solaris */
#endif

#ifdef HAVE_TCPWRAPPERS
#include <tcpd.h>

int deny_severity  = LOG_WARNING;
int allow_severity = -1; /* Don't log at all */

static struct request_info wrap_request;
#endif

#ifdef HAVE_IPV6
static int ai_fam = AF_UNSPEC;
#else
static int ai_fam = AF_INET;
#endif

#define TIMEOUT       1000000 /* Default timeout (us) */
#define TRIES         6       /* Number of attempts to send each packet */
#define TIMEOUT_LIMIT ((1 << TRIES) - 1)

enum
{
    MESSAGE_TYPE_ERROR,
    MESSAGE_TYPE_RETURN,
};

enum
{
    PROTOCOL_UDP,
    PROTOCOL_KCP,
};

struct kcp_context
{
    union sock_addr peeraddr;
    int socket;
};

const char* g_tftpd_progname;
static int g_peer;
static unsigned long g_timeout    = TIMEOUT; /* Current timeout value */
static unsigned long g_rexmtval   = TIMEOUT; /* Basic timeout value */
static unsigned long g_maxtimeout = TIMEOUT_LIMIT * TIMEOUT;
static int g_timeout_quit         = 0;
static sigjmp_buf g_timeoutbuf;
static uint16_t g_rollover_val = 0;

#define PKTSIZE MAX_SEGSIZE + 4
static char g_buf[PKTSIZE];
static char ackbuf[PKTSIZE];
static unsigned int g_max_blksize = MAX_SEGSIZE;

static char tmpbuf[INET6_ADDRSTRLEN], *tmp_p;

static union sock_addr from;
static off_t g_tsize;
static int g_tsize_ok;

static int ndirs;
static const char** dirs;

static int g_secure = 0;
int g_detail        = 0; /* directory list detail */
int g_cancreate     = 0;
int g_unixperms     = 0;
int g_portrange     = 0;
unsigned int portrange_from, portrange_to;
int g_verbosity = 0;
ikcpcb* kcpobj;

struct formats;
#ifdef WITH_REGEX
static struct rule* rewrite_rules = NULL;
#endif

static int tftp_handle(struct tftphdr*, int);
static int tftp_file(struct tftphdr* tp, int size);
static int tftp_list(struct tftphdr* tp, int size);
static int tftp_cmd(struct tftphdr* tp, int size);
static void nak(int, int, int, const char*);
static void timer(int);
static void do_opt(const char*, const char*, char**);
static int get_list(char*);

static int set_blksize(uintmax_t*);
static int set_blksize2(uintmax_t*);
static int set_tsize(uintmax_t*);
static int set_timeout(uintmax_t*);
static int set_utimeout(uintmax_t*);
static int set_rollover(uintmax_t*);
static ikcpcb* kcp_init(struct kcp_context* ctx);
static void kcp_uninit(ikcpcb* kcpobj);
static int kcp_op(const char* buf, int len, ikcpcb* kcp, void* user);

struct options
{
    const char* o_opt;
    int (*o_fnc)(uintmax_t*);
} options[]
    = { { "blksize", set_blksize },   { "blksize2", set_blksize2 }, { "tsize", set_tsize }, { "timeout", set_timeout },
        { "utimeout", set_utimeout }, { "rollover", set_rollover }, { NULL, NULL } };

/* Simple handler for SIGHUP */
static volatile sig_atomic_t caught_sighup = 0;
static void handle_sighup(int sig)
{
    (void)sig; /* Suppress unused warning */
    caught_sighup = 1;
}

/* Handle exit requests by SIGTERM and SIGINT */
static volatile sig_atomic_t exit_signal = 0;
static void handle_exit(int sig)
{
    exit_signal = sig;
}

/* Handle timeout signal or timeout event */
void timer(int sig)
{
    (void)sig; /* Suppress unused warning */
    g_timeout <<= 1;
    if (g_timeout >= g_maxtimeout || g_timeout_quit)
        exit(0);
    siglongjmp(g_timeoutbuf, 1);
}

#ifdef WITH_REGEX
static struct rule* read_remap_rules(const char* file)
{
    FILE* f;
    struct rule* rulep;

    f = fopen(file, "rt");
    if (!f)
    {
        syslog(LOG_ERR, "Cannot open map file: %s: %m", file);
        exit(EX_NOINPUT);
    }
    rulep = parserulefile(f);
    fclose(f);

    return rulep;
}
#endif

/*
 * Rules for locking files; return 0 on success, -1 on failure
 */
static int lock_file(int fd, int lock_write)
{
#if defined(HAVE_FCNTL) && defined(HAVE_F_SETLK_DEFINITION)
    struct flock fl;

    fl.l_type   = lock_write ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0; /* Whole file */
    return fcntl(fd, F_SETLK, &fl);
#elif defined(HAVE_LOCK_SH_DEFINITION)
    return flock(fd, lock_write ? LOCK_EX | LOCK_NB : LOCK_SH | LOCK_NB);
#else
    return 0; /* Hope & pray... */
#endif
}

static void set_socket_nonblock(int fd, int flag)
{
    int err;
    int flags;
#if defined(HAVE_FCNTL) && defined(HAVE_O_NONBLOCK_DEFINITION)
    /* Posixly correct */
    err = ((flags = fcntl(fd, F_GETFL, 0)) < 0)
        || (fcntl(fd, F_SETFL, flag ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) < 0);
#else
    flags = flag ? 1 : 0;
    err   = (ioctl(fd, FIONBIO, &flags) < 0);
#endif
    if (err)
    {
        syslog(LOG_ERR, "Cannot set nonblock flag on socket: %m");
        exit(EX_OSERR);
    }
}

static void pmtu_discovery_off(int fd)
{
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    int pmtu = IP_PMTUDISC_DONT;

    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
#endif
}

/*
 * Receive packet with synchronous timeout; timeout is adjusted
 * to account for time spent waiting.
 */
static int recv_time(int s, void* rbuf, int len, unsigned int flags, unsigned long* timeout_us_p)
{
    fd_set fdset;
    struct timeval tmv, t0, t1;
    int rv, err;
    unsigned long timeout_us = *timeout_us_p;
    unsigned long timeout_left, dt;

    gettimeofday(&t0, NULL);
    timeout_left = timeout_us;

    for (;;)
    {
        FD_ZERO(&fdset);
        FD_SET(s, &fdset);

        do
        {
            tmv.tv_sec  = timeout_left / 1000000;
            tmv.tv_usec = timeout_left % 1000000;

            rv  = select(s + 1, &fdset, NULL, NULL, &tmv);
            err = errno;

            gettimeofday(&t1, NULL);

            dt            = (t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_usec - t0.tv_usec);
            *timeout_us_p = timeout_left = (dt >= timeout_us) ? 1 : (timeout_us - dt);
        } while (rv == -1 && err == EINTR);

        if (rv == 0)
        {
            timer(0); /* Should not return */
            return -1;
        }

        set_socket_nonblock(s, 1);
        rv  = recv(s, rbuf, len, flags);
        err = errno;
        set_socket_nonblock(s, 0);

        if (rv < 0)
        {
            if (E_WOULD_BLOCK(err) || err == EINTR)
            {
                continue; /* Once again, with feeling... */
            }
            else
            {
                errno = err;
                return rv;
            }
        }
        else
        {
            return rv;
        }
    }
}

static int split_port(char** ap, char** pp)
{
    char *a, *p;
    int ret = AF_UNSPEC;

    a = *ap;
#ifdef HAVE_IPV6
    if (is_numeric_ipv6(a))
    {
        if (*a++ != '[')
            return -1;
        *ap = a;
        p   = strrchr(a, ']');
        if (!p)
            return -1;
        *p++ = 0;
        a    = p;
        ret  = AF_INET6;
        p    = strrchr(a, ':');
        if (p)
            *p++ = 0;
    }
    else
#endif
    {
        struct in_addr in;

        p = strrchr(a, ':');
        if (p)
            *p++ = 0;
        if (inet_aton(a, &in))
            ret = AF_INET;
    }
    *pp = p;
    return ret;
}

enum long_only_options
{
    OPT_VERBOSITY = 256,
};

static struct option long_options[] = { { "ipv4", 0, NULL, '4' },        { "ipv6", 0, NULL, '6' },
                                        { "create", 0, NULL, 'c' },      { "secure", 0, NULL, 's' },
                                        { "permissive", 0, NULL, 'p' },  { "verbose", 0, NULL, 'v' },
                                        { "list-detail", 0, NULL, 'D' }, { "verbosity", 1, NULL, OPT_VERBOSITY },
                                        { "version", 0, NULL, 'V' },     { "listen", 0, NULL, 'l' },
                                        { "foreground", 0, NULL, 'L' },  { "address", 1, NULL, 'a' },
                                        { "blocksize", 1, NULL, 'B' },   { "user", 1, NULL, 'u' },
                                        { "umask", 1, NULL, 'U' },       { "refuse", 1, NULL, 'r' },
                                        { "timeout", 1, NULL, 't' },     { "retransmit", 1, NULL, 'T' },
                                        { "port-range", 1, NULL, 'R' },  { "map-file", 1, NULL, 'm' },
                                        { "pidfile", 1, NULL, 'P' },     { NULL, 0, NULL, 0 } };
static const char short_options[]   = "46cspvDVlLa:B:u:U:r:t:T:R:m:P:";

int main(int argc, char** argv)
{
    struct tftphdr* tp;
    struct passwd* pw;
    struct options* opt;
    union sock_addr myaddr;
    struct sockaddr_in bindaddr4;
#ifdef HAVE_IPV6
    struct sockaddr_in6 bindaddr6;
    int force_ipv6 = 0;
#endif
    int n;
    int fd         = -1;
    int fd4        = -1;
    int fd6        = -1;
    int fdmax      = 0;
    int standalone = 0;    /* Standalone (listen) mode */
    int nodaemon   = 0;    /* Do not detach process */
    char* address  = NULL; /* Address to listen to */
    pid_t pid;
    mode_t my_umask = 0;
    int spec_umask  = 0;
    int c;
    int setrv;
    int waittime     = 900;      /* Default time to wait for a connect */
    const char* user = "nobody"; /* Default user */
    char *p, *ep;
#ifdef WITH_REGEX
    char* rewrite_file = NULL;
#endif
    const char* pidfile = NULL;
    u_short tp_opcode;

    /* basename() is way too much of a pain from a portability standpoint */

    p                = strrchr(argv[0], '/');
    g_tftpd_progname = (p && p[1]) ? p + 1 : argv[0];

    openlog(g_tftpd_progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);

    srand(time(NULL) ^ getpid());

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
        switch (c)
        {
        case '4':
            ai_fam = AF_INET;
            break;
#ifdef HAVE_IPV6
        case '6':
            ai_fam     = AF_INET6;
            force_ipv6 = 1;
            break;
#endif
        case 'c':
            g_cancreate = 1;
            break;
        case 'D':
            g_detail = 1;
            break;
        case 's':
            g_secure = 1;
            break;
        case 'p':
            g_unixperms = 1;
            break;
        case 'l':
            standalone = 1;
            break;
        case 'L':
            standalone = 1;
            nodaemon   = 1;
            break;
        case 'a':
            address = optarg;
            break;
        case 't':
            waittime = atoi(optarg);
            break;
        case 'B':
        {
            char* vp;
            g_max_blksize = (unsigned int)strtoul(optarg, &vp, 10);
            if (g_max_blksize < 512 || g_max_blksize > MAX_SEGSIZE || *vp)
            {
                syslog(LOG_ERR, "Bad maximum blocksize value (range 512-%d): %s", MAX_SEGSIZE, optarg);
                exit(EX_USAGE);
            }
        }
        break;
        case 'T':
        {
            char* vp;
            unsigned long tov = strtoul(optarg, &vp, 10);
            if (tov < 10000UL || tov > 255000000UL || *vp)
            {
                syslog(LOG_ERR, "Bad timeout value: %s", optarg);
                exit(EX_USAGE);
            }
            g_rexmtval = g_timeout = tov;
            g_maxtimeout           = g_rexmtval * TIMEOUT_LIMIT;
        }
        break;
        case 'R':
        {
            if (sscanf(optarg, "%u:%u", &portrange_from, &portrange_to) != 2 || portrange_from > portrange_to
                || portrange_to >= 65535)
            {
                syslog(LOG_ERR, "Bad port range: %s", optarg);
                exit(EX_USAGE);
            }
            g_portrange = 1;
        }
        break;
        case 'u':
            user = optarg;
            break;
        case 'U':
            my_umask = strtoul(optarg, &ep, 8);
            if (*ep)
            {
                syslog(LOG_ERR, "Invalid umask: %s", optarg);
                exit(EX_USAGE);
            }
            spec_umask = 1;
            break;
        case 'r':
            for (opt = options; opt->o_opt; opt++)
            {
                if (!strcasecmp(optarg, opt->o_opt))
                {
                    opt->o_opt = ""; /* Don't support this option */
                    break;
                }
            }
            if (!opt->o_opt)
            {
                syslog(LOG_ERR, "Unknown option: %s", optarg);
                exit(EX_USAGE);
            }
            break;
#ifdef WITH_REGEX
        case 'm':
            if (rewrite_file)
            {
                syslog(LOG_ERR, "Multiple -m options");
                exit(EX_USAGE);
            }
            rewrite_file = optarg;
            break;
#endif
        case 'v':
            g_verbosity++;
            break;
        case OPT_VERBOSITY:
            g_verbosity = atoi(optarg);
            break;
        case 'V':
            /* Print configuration to stdout and exit */
            printf("%s\n", TFTPD_CONFIG_STR);
            exit(0);
            break;
        case 'P':
            pidfile = optarg;
            break;
        default:
            syslog(LOG_ERR, "Unknown option: '%c'", optopt);
            break;
        }

    dirs = xmalloc((argc - optind + 1) * sizeof(char*));
    for (ndirs = 0; optind != argc; optind++)
        dirs[ndirs++] = argv[optind];

    dirs[ndirs] = NULL;

    if (g_secure)
    {
        if (ndirs == 0)
        {
            syslog(LOG_ERR, "no -s directory");
            exit(EX_USAGE);
        }
        if (ndirs > 1)
        {
            syslog(LOG_ERR, "too many -s directories");
            exit(EX_USAGE);
        }
        if (chdir(dirs[0]))
        {
            syslog(LOG_ERR, "%s: %m", dirs[0]);
            exit(EX_NOINPUT);
        }
    }

    pw = getpwnam(user);
    if (!pw)
    {
        syslog(LOG_ERR, "no user %s: %m", user);
        exit(EX_NOUSER);
    }

#ifdef WITH_REGEX
    if (rewrite_file)
        rewrite_rules = read_remap_rules(rewrite_file);
#endif

    if (pidfile && !standalone)
    {
        syslog(LOG_WARNING, "not in standalone mode, ignoring pid file");
        pidfile = NULL;
    }

    /* If we're running standalone, set up the input port */
    if (standalone)
    {
        FILE* pf;
#ifdef HAVE_IPV6
        if (ai_fam != AF_INET6)
        {
#endif
            fd4 = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd4 < 0)
            {
                syslog(LOG_ERR, "cannot open IPv4 socket: %m");
                exit(EX_OSERR);
            }
#ifndef __CYGWIN__
            set_socket_nonblock(fd4, 1);
#endif
            memset(&bindaddr4, 0, sizeof bindaddr4);
            bindaddr4.sin_family      = AF_INET;
            bindaddr4.sin_addr.s_addr = INADDR_ANY;
            bindaddr4.sin_port        = htons(IPPORT_TFTP);
#ifdef HAVE_IPV6
        }
        if (ai_fam != AF_INET)
        {
            fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd6 < 0)
            {
                if (fd4 < 0)
                {
                    syslog(LOG_ERR, "cannot open IPv6 socket: %m");
                    exit(EX_OSERR);
                }
                else
                {
                    syslog(LOG_ERR, "cannot open IPv6 socket, disable IPv6: %m");
                }
            }
#ifndef __CYGWIN__
            set_socket_nonblock(fd6, 1);
#endif
            memset(&bindaddr6, 0, sizeof bindaddr6);
            bindaddr6.sin6_family = AF_INET6;
            bindaddr6.sin6_port   = htons(IPPORT_TFTP);
        }
#endif
        if (address)
        {
            char *portptr = NULL, *eportptr;
            int err;
            struct servent* servent;
            unsigned long port;

            address = tfstrdup(address);
            err     = split_port(&address, &portptr);
            switch (err)
            {
            case AF_INET:
#ifdef HAVE_IPV6
                if (fd6 >= 0)
                {
                    close(fd6);
                    fd6 = -1;
                    if (ai_fam == AF_INET6)
                    {
                        syslog(LOG_ERR, "Address %s is not in address family AF_INET6", address);
                        exit(EX_USAGE);
                    }
                    ai_fam = AF_INET;
                }
                break;
            case AF_INET6:
                if (fd4 >= 0)
                {
                    close(fd4);
                    fd4 = -1;
                    if (ai_fam == AF_INET)
                    {
                        syslog(LOG_ERR, "Address %s is not in address family AF_INET", address);
                        exit(EX_USAGE);
                    }
                    ai_fam = AF_INET6;
                }
                break;
#endif
            case AF_UNSPEC:
                break;
            default:
                syslog(LOG_ERR, "Numeric IPv6 addresses need to be enclosed in []");
                exit(EX_USAGE);
            }
            if (!portptr)
                portptr = (char*)"tftp";
            if (*address)
            {
                if (fd4 >= 0)
                {
                    bindaddr4.sin_family = AF_INET;
                    err                  = set_sock_addr(address, (union sock_addr*)&bindaddr4, NULL);
                    if (err)
                    {
                        syslog(LOG_ERR, "cannot resolve local IPv4 bind address: %s, %s", address, gai_strerror(err));
                        exit(EX_NOINPUT);
                    }
                }
#ifdef HAVE_IPV6
                if (fd6 >= 0)
                {
                    bindaddr6.sin6_family = AF_INET6;
                    err                   = set_sock_addr(address, (union sock_addr*)&bindaddr6, NULL);
                    if (err)
                    {
                        if (fd4 >= 0)
                        {
                            syslog(LOG_ERR,
                                   "cannot resolve local IPv6 bind address: %s"
                                   "(%s); using IPv4 only",
                                   address, gai_strerror(err));
                            close(fd6);
                            fd6 = -1;
                        }
                        else
                        {
                            syslog(LOG_ERR,
                                   "cannot resolve local IPv6 bind address: %s"
                                   "(%s)",
                                   address, gai_strerror(err));
                            exit(EX_NOINPUT);
                        }
                    }
                }
#endif
            }
            else
            {
                /* Default to using INADDR_ANY */
            }

            if (portptr && *portptr)
            {
                servent = getservbyname(portptr, "udp");
                if (servent)
                {
                    if (fd4 >= 0)
                        bindaddr4.sin_port = servent->s_port;
#ifdef HAVE_IPV6
                    if (fd6 >= 0)
                        bindaddr6.sin6_port = servent->s_port;
#endif
                }
                else if ((port = strtoul(portptr, &eportptr, 0)) && !*eportptr)
                {
                    if (fd4 >= 0)
                        bindaddr4.sin_port = htons(port);
#ifdef HAVE_IPV6
                    if (fd6 >= 0)
                        bindaddr6.sin6_port = htons(port);
#endif
                }
                else if (!strcmp(portptr, "tftp"))
                {
                    /* It's TFTP, we're OK */
                }
                else
                {
                    syslog(LOG_ERR, "cannot resolve local bind port: %s", portptr);
                    exit(EX_NOINPUT);
                }
            }
        }

        if (fd4 >= 0)
        {
            if (bind(fd4, (struct sockaddr*)&bindaddr4, sizeof(bindaddr4)) < 0)
            {
                syslog(LOG_ERR, "cannot bind to local IPv4 socket: %m");
                exit(EX_OSERR);
            }
        }
#ifdef HAVE_IPV6
        if (fd6 >= 0)
        {
#if defined(IPV6_V6ONLY)
            int on = 1;
            if (fd4 >= 0 || force_ipv6)
                if (setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&on, sizeof(on)))
                    syslog(LOG_ERR, "cannot setsockopt IPV6_V6ONLY %m");
#endif
            if (bind(fd6, (struct sockaddr*)&bindaddr6, sizeof(bindaddr6)) < 0)
            {
                if (fd4 >= 0)
                {
                    syslog(LOG_ERR,
                           "cannot bind to local IPv6 socket,"
                           "IPv6 disabled: %m");
                    close(fd6);
                    fd6 = -1;
                }
                else
                {
                    syslog(LOG_ERR, "cannot bind to local IPv6 socket: %m");
                    exit(EX_OSERR);
                }
            }
        }
#endif
        /* Daemonize this process */
        /* Note: when running in secure mode (-s), we must not chdir, since
           we are already in the proper directory. */
        if (!nodaemon && daemon(g_secure, 0) < 0)
        {
            syslog(LOG_ERR, "cannot daemonize: %m");
            exit(EX_OSERR);
        }
        set_signal(SIGTERM, handle_exit, 0);
        set_signal(SIGINT, handle_exit, 0);
        if (pidfile)
        {
            pf = fopen(pidfile, "w");
            if (!pf)
            {
                syslog(LOG_ERR, "cannot open pid file '%s' for writing: %m", pidfile);
                pidfile = NULL;
            }
            else
            {
                if (fprintf(pf, "%d\n", getpid()) < 0)
                    syslog(LOG_ERR, "error writing pid file '%s': %m", pidfile);
                if (fclose(pf))
                    syslog(LOG_ERR, "error closing pid file '%s': %m", pidfile);
            }
        }
        if (fd6 > fd4)
            fdmax = fd6;
        else
            fdmax = fd4;
    }
    else
    {
        /* 0 is our socket descriptor */
        close(1);
        close(2);
        fd    = 0;
        fdmax = 0;
        /* Note: on Cygwin, select() on a nonblocking socket becomes
           a nonblocking select. */
#ifndef __CYGWIN__
        set_socket_nonblock(fd, 1);
#endif
    }

    /* Disable path MTU discovery */
    pmtu_discovery_off(fd);

    /* This means we don't want to wait() for children */
#ifdef SA_NOCLDWAIT
    set_signal(SIGCHLD, SIG_IGN, SA_NOCLDSTOP | SA_NOCLDWAIT);
#else
    set_signal(SIGCHLD, SIG_IGN, SA_NOCLDSTOP);
#endif

    /* Take SIGHUP and use it to set a variable.  This
       is polled synchronously to make sure we don't
       lose packets as a result. */
    set_signal(SIGHUP, handle_sighup, 0);

    if (spec_umask || !g_unixperms)
        umask(my_umask);

    while (1)
    {
        fd_set readset;
        struct timeval tv_waittime;
        int rv;

        if (exit_signal)
        { /* happens in standalone mode only */
            if (pidfile && unlink(pidfile))
            {
                syslog(LOG_WARNING, "error removing pid file '%s': %m", pidfile);
                exit(EX_OSERR);
            }
            else
            {
                exit(0);
            }
        }

        if (caught_sighup)
        {
            caught_sighup = 0;
            if (standalone)
            {
#ifdef WITH_REGEX
                if (rewrite_file)
                {
                    freerules(rewrite_rules);
                    rewrite_rules = read_remap_rules(rewrite_file);
                }
#endif
            }
            else
            {
                /* Return to inetd for respawn */
                exit(0);
            }
        }

        FD_ZERO(&readset);
        if (standalone)
        {
            if (fd4 >= 0)
            {
                FD_SET(fd4, &readset);
#ifdef __CYGWIN__
                /* On Cygwin, select() on a nonblocking socket returns
                   immediately, with a rv of 0! */
                set_socket_nonblock(fd4, 0);
#endif
            }
            if (fd6 >= 0)
            {
                FD_SET(fd6, &readset);
#ifdef __CYGWIN__
                /* On Cygwin, select() on a nonblocking socket returns
                   immediately, with a rv of 0! */
                set_socket_nonblock(fd6, 0);
#endif
            }
        }
        else
        { /* fd always 0 */
            fd = 0;
#ifdef __CYGWIN__
            /* On Cygwin, select() on a nonblocking socket returns
               immediately, with a rv of 0! */
            set_socket_nonblock(fd, 0);
#endif
            FD_SET(fd, &readset);
        }
        tv_waittime.tv_sec  = waittime;
        tv_waittime.tv_usec = 0;

        /* Never time out if we're in standalone mode */
        rv = select(fdmax + 1, &readset, NULL, NULL, standalone ? NULL : &tv_waittime);
        if (rv == -1 && errno == EINTR)
            continue; /* Signal caught, reloop */

        if (rv == -1)
        {
            syslog(LOG_ERR, "select loop: %m");
            exit(EX_IOERR);
        }
        else if (rv == 0)
        {
            exit(0); /* Timeout, return to inetd */
        }

        if (standalone)
        {
            if ((fd4 >= 0) && FD_ISSET(fd4, &readset))
                fd = fd4;
            else if ((fd6 >= 0) && FD_ISSET(fd6, &readset))
                fd = fd6;
            else /* not in set ??? */
                continue;
        }
#ifdef __CYGWIN__
        /* On Cygwin, select() on a nonblocking socket returns
           immediately, with a rv of 0! */
        set_socket_nonblock(fd, 0);
#endif

        memset(g_buf, 0, sizeof(g_buf));
        n = myrecvfrom(fd, g_buf, sizeof(g_buf), 0, &from, &myaddr);

        if (n < 0)
        {
            if (E_WOULD_BLOCK(errno) || errno == EINTR)
            {
                continue; /* Again, from the top */
            }
            else
            {
                syslog(LOG_ERR, "recvfrom: %m");
                exit(EX_IOERR);
            }
        }
#ifdef HAVE_IPV6
        if ((from.sa.sa_family != AF_INET) && (from.sa.sa_family != AF_INET6))
        {
            syslog(LOG_ERR,
                   "received address was not AF_INET/AF_INET6,"
                   " please check your inetd config");
#else
        if (from.sa.sa_family != AF_INET)
        {
            syslog(LOG_ERR,
                   "received address was not AF_INET,"
                   " please check your inetd config");
#endif
            exit(EX_PROTOCOL);
        }

        if (standalone)
        {
            if ((from.sa.sa_family == AF_INET) && (myaddr.si.sin_addr.s_addr == INADDR_ANY))
            {
                /* myrecvfrom() didn't capture the source address; but we might
                   have bound to a specific address, if so we should use it */
                memcpy(SOCKADDR_P(&myaddr), &bindaddr4.sin_addr, sizeof(bindaddr4.sin_addr));
#ifdef HAVE_IPV6
            }
            else if ((from.sa.sa_family == AF_INET6) && IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)SOCKADDR_P(&myaddr)))
            {
                memcpy(SOCKADDR_P(&myaddr), &bindaddr6.sin6_addr, sizeof(bindaddr6.sin6_addr));
#endif
            }
        }

        tp        = (struct tftphdr*)g_buf;
        tp_opcode = ntohs(tp->th_opcode);
        if (tp_opcode == DELE || tp_opcode == CWD || tp_opcode == LIST || tp_opcode == MKD || tp_opcode == RMD
            || tp_opcode == PWD || tp_opcode == CDUP || tp_opcode == SIZE || tp_opcode == CHMOD)
        {
            g_peer = fd;
            if (connect(g_peer, &from.sa, SOCKLEN(&from)) < 0)
            {
                syslog(LOG_ERR, "connect: %m");
                continue;
            }

            tftp_handle(tp, n);
            continue;
        }
        /*
         * Now that we have read the request packet from the UDP
         * socket, we fork and go back to listening to the socket.
         */
        pid = fork();
        if (pid < 0)
        {
            syslog(LOG_ERR, "fork: %m");
            exit(EX_OSERR); /* Return to inetd, just in case */
        }
        else if (pid == 0)
            break; /* Child exit, parent loop */
    }

    /* Child process: handle the actual request here */

    /* Ignore SIGHUP */
    set_signal(SIGHUP, SIG_IGN, 0);

    /* Make sure the log socket is still connected.  This has to be
       done before the chroot, while /dev/log is still accessible.
       When not running standalone, there is little chance that the
       syslog daemon gets restarted by the time we get here. */
    if (g_secure && standalone)
    {
        closelog();
        openlog(g_tftpd_progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

#ifdef HAVE_TCPWRAPPERS
    /* Verify if this was a legal request for us.  This has to be
       done before the chroot, while /etc is still accessible. */
    request_init(&wrap_request, RQ_DAEMON, g_tftpd_progname, RQ_FILE, fd, RQ_CLIENT_SIN, &from, RQ_SERVER_SIN, &myaddr,
                 0);
    sock_methods(&wrap_request);

    tmp_p = (char*)inet_ntop(myaddr.sa.sa_family, SOCKADDR_P(&myaddr), tmpbuf, INET6_ADDRSTRLEN);
    if (!tmp_p)
    {
        tmp_p = tmpbuf;
        strcpy(tmpbuf, "???");
    }
    if (hosts_access(&wrap_request) == 0)
    {
        if (deny_severity != -1)
            syslog(deny_severity, "connection refused from %s", tmp_p);
        exit(EX_NOPERM); /* Access denied */
    }
    else if (allow_severity != -1)
    {
        syslog(allow_severity, "connect from %s", tmp_p);
    }
#endif

    /* Close file descriptors we don't need */
    close(fd);

    /* Get a socket.  This has to be done before the chroot(), since
       some systems require access to /dev to create a socket. */

    g_peer = socket(myaddr.sa.sa_family, SOCK_DGRAM, 0);
    if (g_peer < 0)
    {
        syslog(LOG_ERR, "socket: %m");
        exit(EX_IOERR);
    }

    /* Set up the supplementary group access list if possible */
    /* /etc/group still need to be accessible at this point */
#ifdef HAVE_INITGROUPS
    setrv = initgroups(user, pw->pw_gid);
    if (setrv)
    {
        syslog(LOG_ERR, "cannot set groups for user %s", user);
        exit(EX_OSERR);
    }
#else
#ifdef HAVE_SETGROUPS
    if (setgroups(0, NULL))
    {
        syslog(LOG_ERR, "cannot clear group list");
    }
#endif
#endif

#if 0
    /* Chroot and drop privileges */
    if (g_secure)
    {
        if (chroot("."))
        {
            syslog(LOG_ERR, "chroot: %m");
            exit(EX_OSERR);
        }
#ifdef __CYGWIN__
        chdir("/"); /* Cygwin chroot() bug workaround */
#endif
    }
#endif

#ifdef HAVE_SETREGID
    setrv = setregid(pw->pw_gid, pw->pw_gid);
#else
    setrv = setegid(pw->pw_gid) || setgid(pw->pw_gid);
#endif

#ifdef HAVE_SETREUID
    setrv = setrv || setreuid(pw->pw_uid, pw->pw_uid);
#else
    /* Important: setuid() must come first */
    setrv = setrv || setuid(pw->pw_uid) || (geteuid() != pw->pw_uid && seteuid(pw->pw_uid));
#endif

    if (setrv)
    {
        syslog(LOG_ERR, "cannot drop privileges: %m");
        exit(EX_OSERR);
    }

    /* Process the request... */
    if (pick_port_bind(g_peer, &myaddr, portrange_from, portrange_to) < 0)
    {
        syslog(LOG_ERR, "bind: %m");
        exit(EX_IOERR);
    }

    if (connect(g_peer, &from.sa, SOCKLEN(&from)) < 0)
    {
        syslog(LOG_ERR, "connect: %m");
        exit(EX_IOERR);
    }

    /* Disable path MTU discovery */
    pmtu_discovery_off(g_peer);

    struct kcp_context ctx;
    memcpy(&ctx.peeraddr, &from, sizeof(union sock_addr));
    ctx.socket = g_peer;

    kcpobj    = kcp_init(&ctx);
    tp        = (struct tftphdr*)g_buf;
    tp_opcode = ntohs(tp->th_opcode);
    if (tp_opcode == RRQ || tp_opcode == WRQ)
        tftp_handle(tp, n);

    kcp_uninit(kcpobj);
    exit(0);
}

static char* rewrite_access(char*, int, int, const char**);
static int validate_access(char*, int, const struct formats*, const char**);
static void tftp_sendfile(const struct formats*, struct tftphdr*, int);
static void tftp_recvfile(const struct formats*, struct tftphdr*, int);

struct formats
{
    const char* f_mode;
    char* (*f_rewrite)(char*, int, int, const char**);
    int (*f_validate)(char*, int, const struct formats*, const char**);
    void (*f_send)(const struct formats*, struct tftphdr*, int);
    void (*f_recv)(const struct formats*, struct tftphdr*, int);
    int f_convert;
};
static const struct formats formats[]
    = { { "netascii", rewrite_access, validate_access, tftp_sendfile, tftp_recvfile, 1 },
        { "octet", rewrite_access, validate_access, tftp_sendfile, tftp_recvfile, 0 },
        { NULL, NULL, NULL, NULL, NULL, 0 } };

/*
 * Handle initial connection protocol.
 */
int tftp_handle(struct tftphdr* tp, int size)
{
    int ret           = 0;
    u_short tp_opcode = ntohs(tp->th_opcode);
    switch (tp_opcode)
    {
    case RRQ:
    case WRQ:
        ret = tftp_file(tp, size);
        break;

    case LIST:
        ret = tftp_list(tp, size);
        break;

    case DELE:
    case CWD:
    case MKD:
    case RMD:
    case PWD:
    case CDUP:
    case SIZE:
    case CHMOD:
        ret = tftp_cmd(tp, size);
        break;

    default:
        syslog(LOG_ERR, "unknown operation code: %d", tp_opcode);
        break;
    }

    return ret;
}

static int get_list(char* listbuf)
{
    struct dirent* dt = NULL;
    struct stat sbuf;
    int off  = 0;
    DIR* dir = opendir(".");
    if (dir == NULL)
    {
        nak(PROTOCOL_UDP, MESSAGE_TYPE_ERROR, errno, strerror(errno));
        return -1;
    }

    while ((dt = readdir(dir)) != NULL)
    {
        /*权限获取*/
        if (lstat(dt->d_name, &sbuf) < 0)
        {
            continue;
        }

        /*过滤 '.'和'..' 目录 和文件*/
        if (dt->d_name[0] == '.')
        {
            continue;
        }
        if (g_detail)
        {
            /*获取权限位信息*/
            const char* perms = statbuf_get_perms(&sbuf);

            /*权限位*/
            off += sprintf(listbuf + off, "%s ", perms);
            /*硬连接数 uid gid*/
            off += sprintf(listbuf + off, "%3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
            /*文件大小*/
            off += sprintf(listbuf + off, "%-8lu ", (unsigned long)sbuf.st_size);

            /*时间格式化*/
            const char* datebuf = statbuf_get_date(&sbuf);

            off += sprintf(listbuf + off, "%s ", datebuf);

            /*格式化添加文件名*/

            /*判读是否连接文件，如果是连接文件添加指向的文件名*/
            if (S_ISLNK(sbuf.st_mode))
            {
                char real_file_buf[64] = { 0 };
                readlink(dt->d_name, real_file_buf, sizeof(real_file_buf));
                off += sprintf(listbuf + off, "%s -> %s\r\n", dt->d_name, real_file_buf);
            }
            else
            {
                off += sprintf(listbuf + off, "%s\r\n", dt->d_name);
            }

        } /*end if*/
        else
        {
            off += sprintf(listbuf + off, "%s\r\n", dt->d_name);
        }
    } /*end while*/

    printf("ls -l \r\n-----------------------------------------------------------\n");
    printf("%s", listbuf);
    printf("-----------------------------------------------------------\n");

    /*关闭目录*/
    closedir(dir);
    return off;
}

int tftp_list(struct tftphdr* tp, int size)
{
    struct tftphdr* dp;
    struct tftphdr* ap;       /* ack packet */
    static u_short block = 1; /* Static to avoid longjmp funnies */
    u_short ap_opcode, ap_block;
    unsigned long r_timeout;
    int transfersize, n, remain;
    char buf[PKTSIZE] = { 0 };
    dp                = (struct tftphdr*)g_buf;

    remain = get_list(buf);
    if (remain <= 0)
    {
        nak(PROTOCOL_UDP, MESSAGE_TYPE_ERROR, ECOMM, "Could not get directory list");
        return -1;
    }

    do
    {
        dp->th_opcode = htons((u_short)DATA);
        dp->th_block  = htons((u_short)block);
        transfersize  = (remain < SEGSIZE) ? remain : SEGSIZE;
        memcpy(dp->th_data, buf + SEGSIZE * (block - 1), transfersize);

        g_timeout = g_rexmtval;
        (void)sigsetjmp(g_timeoutbuf, 1);

        r_timeout = g_timeout;
        if (send(g_peer, dp, transfersize + 4, 0) != transfersize + 4)
        {
            syslog(LOG_WARNING, "tftpd: write: %m");
            return -1;
        }

        for (;;)
        {
            n = recv_time(g_peer, ackbuf, sizeof(ackbuf), 0, &r_timeout);
            if (n < 0)
            {
                syslog(LOG_WARNING, "tftpd: read(ack): %m");
                return -1;
            }
            ap        = (struct tftphdr*)ackbuf;
            ap_opcode = ntohs((u_short)ap->th_opcode);
            ap_block  = ntohs((u_short)ap->th_block);

            if (ap_opcode == ERROR)
                return -1;

            if (ap_opcode == ACK)
            {
                if (ap_block == block)
                {
                    break;
                }
                /* Re-synchronize with the other side */
                (void)synchnet(g_peer);
                /*
                 * RFC1129/RFC1350: We MUST NOT re-send the DATA
                 * packet in response to an invalid ACK.  Doing so
                 * would cause the Sorcerer's Apprentice bug.
                 */
            }
        }

        if (!++block)
            block = g_rollover_val;

        remain -= SEGSIZE;
    } while (transfersize == SEGSIZE);

    return 0;
}

int tftp_cmd(struct tftphdr* tp, int size)
{
    int retCode = 0;
    char* stuff;
    stuff             = (char*)&(tp->th_stuff);
    u_short tp_opcode = ntohs(tp->th_opcode);

    switch (tp_opcode)
    {
    case DELE:
        syslog(LOG_INFO, "DELE: %s", stuff);
        printf("DELE: %s\n", stuff);
        {
            struct stat st;
            if (stat(stuff, &st) < 0)
            {
                retCode = -1;
            }
            else
            {

                if ((st.st_mode & S_IFMT) == S_IFDIR)
                {
                    if (rmdir(stuff) < 0)
                    {
                        retCode = -1;
                    }
                    else
                    {
                        retCode = 0;
                    }
                }
                else
                {

                    if (unlink(stuff) < 0)
                    {
                        retCode = -1;
                    }
                    else
                    {
                        retCode = 0;
                    }
                }
            }

            if (retCode == -1)
            {
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_FILEFAIL, strerror(errno));
            }
            else if (retCode == 0)
            {
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_DELEOK, "Delete operation successful");
            }
        }
        break;

    case CWD:
        syslog(LOG_INFO, "CWD: %s", stuff);
        printf("CWD: %s\n", stuff);
        //更改用户目录
        if (chdir(stuff) < 0)
        {
            retCode = -1;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_NOPERM, strerror(errno));
        }
        else
        {
            retCode = 0;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_CWDOK, "Directory successfully changed.");
        }
        break;

    case LIST:
        syslog(LOG_INFO, "LIST: %s", stuff);
        printf("LIST: %s\n", stuff);
        break;
    case MKD:
        syslog(LOG_INFO, "MKD: %s", stuff);
        printf("MKD: %s\n", stuff);
        // 0777 & umask
        if (mkdir(stuff, 0777) < 0)
        {
            retCode = -1;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_FILEFAIL, strerror(errno));
        }
        else
        {
            retCode = 0;
            char path[MAXPATHLEN];
            /*判断是否绝对路径*/
            if (stuff[0] == '/')
            {
                sprintf(path, "\"%s\" created", stuff);
            }
            else
            {
                char dir[MAXPATHLEN] = { 0 };
                getcwd(dir, sizeof(dir));

                if (dir[strlen(dir) - 1] == '/')
                {
                    sprintf(path, "\"%s%s\" created", dir, stuff);
                }
                else
                {
                    sprintf(path, "\"%s/%s\" created", dir, stuff);
                }
            }
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_MKDIROK, path);
        }
        break;
    case RMD:
        syslog(LOG_INFO, "RMD: %s", stuff);
        printf("RMD: %s\n", stuff);
        if (rmdir(stuff) < 0)
        {
            retCode = -1;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_FILEFAIL, strerror(errno));
        }
        else
        {
            retCode = 0;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_RMDIROK, "Remove directory operation successful.");
        }
        break;
    case PWD:
        syslog(LOG_INFO, "PWD: %s", stuff);
        printf("PWD: %s\n", stuff);
        {
            char path[MAXPATHLEN];
            if (getcwd(path, sizeof path) == (char*)NULL)
            {
                retCode = -1;
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_FILEFAIL, strerror(errno));
            }
            else
            {
                retCode = 0;
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_PWDOK, path);
            }
        }
        break;
    case CDUP:
        syslog(LOG_INFO, "CDUP: %s", stuff);
        printf("CDUP: %s\n", stuff);
        //更改用户目录
        if (chdir("..") < 0)
        {
            retCode = -1;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_NOPERM, strerror(errno));
        }
        else
        {
            retCode = 0;
            nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_CWDOK, "Directory successfully changed.");
        }
        break;
    case SIZE:
        syslog(LOG_INFO, "SIZE: %s", stuff);
        printf("SIZE: %s\n", stuff);
        {
            struct stat stbuf;
            if (stat(stuff, &stbuf) < 0)
            {
                retCode = -1;
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_NOPERM, strerror(errno));
            }
            else
            {
                char data[1024];
                /*如果不是普通文件则返回错误*/
                if (!S_ISREG(stbuf.st_mode))
                {
                    retCode = -1;
                    sprintf(data, "%s is not a plain file.", stuff);
                    nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_NOPERM, data);
                }
                else
                {
                    retCode = 0;
                    sprintf(data, "%ld", stbuf.st_size);
                    nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_SIZEOK, data);
                }
            }
        }
        break;
    case CHMOD:
        syslog(LOG_INFO, "CHMOD: %s", stuff);
        printf("CHMOD: %s\n", stuff);
        {
            char* tmp             = stuff;
            char mode[32]         = { 0 };
            char path[MAXPATHLEN] = { 0 };
            unsigned int modeVal  = 0;
            strcpy(mode, tmp);
            tmp += (strlen(mode) + 1);
            strcpy(path, tmp);
            modeVal = strtol(mode, NULL, 8);
            modeVal = modeVal & 0777;

            if (chmod(path, modeVal) < 0)
            {
                retCode = -1;
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_NOPERM, strerror(errno));
            }
            else
            {
                retCode = 0;
                nak(PROTOCOL_UDP, MESSAGE_TYPE_RETURN, TFTP_CHMODOK, "Permissions successfully changed.");
            }
        }
        break;

    default:
        break;
    }

    return retCode;
}

int tftp_file(struct tftphdr* tp, int size)
{
    char *cp, *end;
    int argn, ecode;
    const struct formats* pf = NULL;
    char* origfilename;
    char *filename, *mode = NULL;
    const char* errmsgptr;
    u_short tp_opcode = ntohs(tp->th_opcode);

    char *val = NULL, *opt = NULL;
    char* ap = ackbuf + 2;

    ((struct tftphdr*)ackbuf)->th_opcode = htons(OACK);

    origfilename = cp = (char*)&(tp->th_stuff);
    argn              = 0;

    end = (char*)tp + size;

    while (cp < end && *cp)
    {
        do
        {
            cp++;
        } while (cp < end && *cp);

        if (*cp)
        {
            nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EBADOP, "Request not null-terminated");
            ikcp_release(kcpobj);
            exit(0);
        }

        argn++;
        if (argn == 1)
        {
            mode = ++cp;
        }
        else if (argn == 2)
        {
            for (cp = mode; *cp; cp++)
                *cp = tolower(*cp);
            for (pf = formats; pf->f_mode; pf++)
            {
                if (!strcmp(pf->f_mode, mode))
                    break;
            }
            if (!pf->f_mode)
            {
                nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EBADOP, "Unknown mode");
                ikcp_release(kcpobj);
                exit(0);
            }
            if (!(filename = (*pf->f_rewrite)(origfilename, tp_opcode, from.sa.sa_family, &errmsgptr)))
            {
                nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EACCESS, errmsgptr); /* File denied by mapping rule */
                ikcp_release(kcpobj);
                exit(0);
            }
            if (g_verbosity >= 1)
            {
                tmp_p = (char*)inet_ntop(from.sa.sa_family, SOCKADDR_P(&from), tmpbuf, INET6_ADDRSTRLEN);
                if (!tmp_p)
                {
                    tmp_p = tmpbuf;
                    strcpy(tmpbuf, "???");
                }
                printf("%s from %s filename %s\n", tp_opcode == WRQ ? "WRQ" : "RRQ", tmp_p, filename);
                if (filename == origfilename || !strcmp(filename, origfilename))
                    syslog(LOG_NOTICE, "%s from %s filename %s\n", tp_opcode == WRQ ? "WRQ" : "RRQ", tmp_p, filename);
                else
                    syslog(LOG_NOTICE, "%s from %s filename %s remapped to %s\n", tp_opcode == WRQ ? "WRQ" : "RRQ",
                           tmp_p, origfilename, filename);
            }
            ecode = (*pf->f_validate)(filename, tp_opcode, pf, &errmsgptr);
            if (ecode)
            {
                nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, ecode, errmsgptr);
                ikcp_release(kcpobj);
                exit(0);
            }
            opt = ++cp;
        }
        else if (argn & 1)
        {
            val = ++cp;
        }
        else
        {
            do_opt(opt, val, &ap);
            opt = ++cp;
        }
    }

    if (!pf)
    {
        nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EBADOP, "Missing mode");
        ikcp_release(kcpobj);
        exit(0);
    }

    if (ap != (ackbuf + 2))
    {
        if (tp_opcode == WRQ)
            (*pf->f_recv)(pf, (struct tftphdr*)ackbuf, ap - ackbuf);
        else
            (*pf->f_send)(pf, (struct tftphdr*)ackbuf, ap - ackbuf);
    }
    else
    {
        if (tp_opcode == WRQ)
            (*pf->f_recv)(pf, NULL, 0);
        else
            (*pf->f_send)(pf, NULL, 0);
    }
    exit(0); /* Request completed */
}

static int blksize_set;

/*
 * Set a non-standard block size (c.f. RFC2348)
 */
static int set_blksize(uintmax_t* vp)
{
    uintmax_t sz = *vp;

    if (blksize_set)
        return 0;

    if (sz < 8)
        return 0;
    else if (sz > g_max_blksize)
        sz = g_max_blksize;

    *vp = segsize = sz;
    blksize_set   = 1;
    return 1;
}

/*
 * Set a power-of-two block size (nonstandard)
 */
static int set_blksize2(uintmax_t* vp)
{
    uintmax_t sz = *vp;

    if (blksize_set)
        return 0;

    if (sz < 8)
        return (0);
    else if (sz > g_max_blksize)
        sz = g_max_blksize;
    else

        /* Convert to a power of two */
        if (sz & (sz - 1))
    {
        unsigned int sz1 = 1;
        /* Not a power of two - need to convert */
        while (sz >>= 1)
            sz1 <<= 1;
        sz = sz1;
    }

    *vp = segsize = sz;
    blksize_set   = 1;
    return 1;
}

/*
 * Set the block number rollover value
 */
static int set_rollover(uintmax_t* vp)
{
    uintmax_t ro = *vp;

    if (ro > 65535)
        return 0;

    g_rollover_val = (uint16_t)ro;
    return 1;
}

/*
 * Return a file size (c.f. RFC2349)
 * For netascii mode, we don't know the size ahead of time;
 * so reject the option.
 */
static int set_tsize(uintmax_t* vp)
{
    uintmax_t sz = *vp;

    if (!g_tsize_ok)
        return 0;

    if (sz == 0)
        sz = g_tsize;

    *vp = sz;
    return 1;
}

/*
 * Set the timeout (c.f. RFC2349).  This is supposed
 * to be the (default) retransmission timeout, but being an
 * integer in seconds it seems a bit limited.
 */
static int set_timeout(uintmax_t* vp)
{
    uintmax_t to = *vp;

    if (to < 1 || to > 255)
        return 0;

    g_rexmtval = g_timeout = to * 1000000UL;
    g_maxtimeout           = g_rexmtval * TIMEOUT_LIMIT;

    return 1;
}

/* Similar, but in microseconds.  We allow down to 10 ms. */
static int set_utimeout(uintmax_t* vp)
{
    uintmax_t to = *vp;

    if (to < 10000UL || to > 255000000UL)
        return 0;

    g_rexmtval = g_timeout = to;
    g_maxtimeout           = g_rexmtval * TIMEOUT_LIMIT;

    return 1;
}

/*
 * Conservative calculation for the size of a buffer which can hold an
 * arbitrary integer
 */
#define OPTBUFSIZE (sizeof(uintmax_t) * CHAR_BIT / 3 + 3)

/*
 * Parse RFC2347 style options; we limit the arguments to positive
 * integers which matches all our current options.
 */
static void do_opt(const char* opt, const char* val, char** ap)
{
    struct options* po;
    char retbuf[OPTBUFSIZE];
    char* p = *ap;
    size_t optlen, retlen;
    char* vend;
    uintmax_t v;

    /* Global option-parsing variables initialization */
    blksize_set = 0;

    if (!*opt || !*val)
        return;

    errno = 0;
    v     = strtoumax(val, &vend, 10);
    if (*vend || errno == ERANGE)
        return;

    for (po = options; po->o_opt; po++)
        if (!strcasecmp(po->o_opt, opt))
        {
            if (po->o_fnc(&v))
            {
                optlen = strlen(opt);
                retlen = sprintf(retbuf, "%" PRIuMAX, v);

                if (p + optlen + retlen + 2 >= ackbuf + sizeof(ackbuf))
                {
                    nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EOPTNEG, "Insufficient space for options");
                    ikcp_release(kcpobj);
                    exit(0);
                }

                memcpy(p, opt, optlen + 1);
                p += optlen + 1;
                memcpy(p, retbuf, retlen + 1);
                p += retlen + 1;
            }
            else
            {
                nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, EOPTNEG, "Unsupported option(s) requested");
                ikcp_release(kcpobj);
                exit(0);
            }
            break;
        }

    *ap = p;
}

#ifdef WITH_REGEX

/*
 * This is called by the remap engine when it encounters macros such
 * as \i.  It should write the output in "output" if non-NULL, and
 * return the length of the output (generated or not).
 *
 * Return -1 on failure.
 */
static int rewrite_macros(char macro, char* output)
{
    char *p, tb[INET6_ADDRSTRLEN];
    int l = 0;

    switch (macro)
    {
    case 'i':
        p = (char*)inet_ntop(from.sa.sa_family, SOCKADDR_P(&from), tb, INET6_ADDRSTRLEN);
        if (output && p)
            strcpy(output, p);
        if (!p)
            return 0;
        else
            return strlen(p);

    case 'x':
        if (output)
        {
            if (from.sa.sa_family == AF_INET)
            {
                sprintf(output, "%08lX", (unsigned long)ntohl(from.si.sin_addr.s_addr));
                l = 8;
#ifdef HAVE_IPV6
            }
            else
            {
                unsigned char* c = (unsigned char*)SOCKADDR_P(&from);
                p                = tb;
                for (l = 0; l < 16; l++)
                {
                    sprintf(p, "%02X", *c);
                    c++;
                    p += 2;
                }
                strcpy(output, tb);
                l = strlen(tb);
#endif
            }
        }
        return l;

    default:
        return -1;
    }
}

/*
 * Modify the filename, if applicable.  If it returns NULL, deny the access.
 */
static char* rewrite_access(char* filename, int mode, int af, const char** msg)
{
    if (rewrite_rules)
    {
        char* newname = rewrite_string(filename, rewrite_rules, mode != RRQ ? 'P' : 'G', af, rewrite_macros, msg);
        filename      = newname;
    }
    return filename;
}

#else
static char* rewrite_access(char* filename, int mode, int af, const char** msg)
{
    (void)mode; /* Avoid warning */
    (void)msg;
    (void)af;
    return filename;
}
#endif

static FILE* file;
/*
 * Validate file access.  Since we
 * have no uid or gid, for now require
 * file to exist and be publicly
 * readable/writable, unless -p specified.
 * If we were invoked with arguments
 * from inetd then the file must also be
 * in one of the given directory prefixes.
 * Note also, full path name must be
 * given as we have no login directory.
 */
static int validate_access(char* filename, int mode, const struct formats* pf, const char** errmsg)
{
    struct stat stbuf;
    int i, len;
    int fd, wmode, rmode;
    char* cp;
    const char** dirp;
    char stdio_mode[3];

    g_tsize_ok = 0;
    *errmsg    = NULL;

    if (!g_secure)
    {
        if (*filename != '/')
        {
            *errmsg = "Only absolute filenames allowed";
            return (EACCESS);
        }

        /*
         * prevent tricksters from getting around the directory
         * restrictions
         */
        len = strlen(filename);
        for (i = 1; i < len - 3; i++)
        {
            cp = filename + i;
            if (*cp == '.' && memcmp(cp - 1, "/../", 4) == 0)
            {
                *errmsg = "Reverse path not allowed";
                return (EACCESS);
            }
        }

        for (dirp = dirs; *dirp; dirp++)
            if (strncmp(filename, *dirp, strlen(*dirp)) == 0)
                break;
        if (*dirp == 0 && dirp != dirs)
        {
            *errmsg = "Forbidden directory";
            return (EACCESS);
        }
    }

    /*
     * We use different a different permissions scheme if `g_cancreate' is
     * set.
     */
    wmode = O_WRONLY | (g_cancreate ? O_CREAT : 0) | (pf->f_convert ? O_TEXT : O_BINARY);
    rmode = O_RDONLY | (pf->f_convert ? O_TEXT : O_BINARY);

#ifndef HAVE_FTRUNCATE
    wmode |= O_TRUNC; /* This really sucks on a dupe */
#endif

    fd = open(filename, mode == RRQ ? rmode : wmode, 0666);
    if (fd < 0)
    {
        switch (errno)
        {
        case ENOENT:
        case ENOTDIR:
            return ENOTFOUND;
        case ENOSPC:
            return ENOSPACE;
        case EEXIST:
            return EEXISTS;
        default:
            return errno + 100;
        }
    }

    if (fstat(fd, &stbuf) < 0)
        exit(EX_OSERR); /* This shouldn't happen */

    /* A duplicate RRQ or (worse!) WRQ packet could really cause havoc... */
    if (lock_file(fd, mode != RRQ))
        exit(0);

    if (mode == RRQ)
    {
        if (!g_unixperms && (stbuf.st_mode & (S_IREAD >> 6)) == 0)
        {
            *errmsg = "File must have global read permissions";
            return (EACCESS);
        }
        g_tsize = stbuf.st_size;
        /* We don't know the tsize if conversion is needed */
        g_tsize_ok = !pf->f_convert;
    }
    else
    {
        if (!g_unixperms)
        {
            if ((stbuf.st_mode & (S_IWRITE >> 6)) == 0)
            {
                *errmsg = "File must have global write permissions";
                return (EACCESS);
            }
        }

#ifdef HAVE_FTRUNCATE
        /* We didn't get to truncate the file at open() time */
        if (ftruncate(fd, (off_t)0))
        {
            *errmsg = "Cannot reset file size";
            return (EACCESS);
        }
#endif
        g_tsize    = 0;
        g_tsize_ok = 1;
    }

    stdio_mode[0] = (mode == RRQ) ? 'r' : 'w';
    stdio_mode[1] = (pf->f_convert) ? 't' : 'b';
    stdio_mode[2] = '\0';

    file = fdopen(fd, stdio_mode);
    if (file == NULL)
        exit(EX_OSERR); /* Internal error */

    return (0);
}

/*
 * Send the requested file.
 */
static void tftp_sendfile(const struct formats* pf, struct tftphdr* oap, int oacklen)
{
    struct tftphdr* dp;
    struct tftphdr* ap;       /* ack packet */
    static u_short block = 1; /* Static to avoid longjmp funnies */
    u_short ap_opcode, ap_block;
    int size;
    int recvLen = 0;
    int kcpRecv = 0;
    socklen_t fromlen;

    if (oap)
    {
        if (ikcp_send(kcpobj, (char*)oap, oacklen) < 0)
        {
            syslog(LOG_WARNING, "tftpd: oack: %m\n");
            goto abort;
        }
        ikcp_update(kcpobj, iclock());
    }

    // printf("tftpd: sendfile\n");
    dp = r_init();
    do
    {
        size = readit(file, &dp, pf->f_convert);
        if (size < 0)
        {
            nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, errno + 100, NULL);
            goto abort;
        }
        dp->th_opcode = htons((u_short)DATA);
        dp->th_block  = htons((u_short)block);

    update:
        ikcp_update(kcpobj, iclock());
        if (kcpobj->state == (IUINT32)-1)
        {
            syslog(LOG_ERR, "network timeout \n");
            printf("network timeout \n");
            goto abort;
        }

        recvLen = recvfrom(g_peer, ackbuf, sizeof(ackbuf), MSG_DONTWAIT, &from.sa, &fromlen);
        if (recvLen > 0)
        {
            ikcp_input(kcpobj, ackbuf, recvLen);
        }
        kcpRecv = ikcp_recv(kcpobj, ackbuf, sizeof(ackbuf));
        if (kcpRecv > 0)
        {
            ap        = (struct tftphdr*)ackbuf;
            ap_opcode = ntohs((u_short)ap->th_opcode);
            ap_block  = ntohs((u_short)ap->th_block);

            if (ap_opcode == ERROR)
                goto abort;

            if (ap_opcode == ACK)
            {
                printf("recv ock \n");
            }
        }

        if (ikcp_waitsnd(kcpobj) < kcpobj->snd_wnd)
        {
            if (ikcp_send(kcpobj, (char*)dp, size + 4) < 0)
            {
                syslog(LOG_WARNING, "tftpd: write: %m");
                goto abort;
            }
            printf("[%d] send file block:%d and size: %d\n", ikcp_waitsnd(kcpobj), block, size);
            read_ahead(file, pf->f_convert);
            usleep(2000);
        }
        else
        {
            usleep(10000);
            goto update;
        }

        if (!++block)
            block = g_rollover_val;
    } while (size == segsize);
    ikcp_update(kcpobj, iclock());
    ikcp_flush(kcpobj);
    while (!iqueue_is_empty(&kcpobj->snd_buf) || !iqueue_is_empty(&kcpobj->rcv_buf))
    {
        ikcp_update(kcpobj, iclock());
        recvLen = recvfrom(g_peer, ackbuf, sizeof(ackbuf), MSG_DONTWAIT, &from.sa, &fromlen);
        if (recvLen > 0)
        {
            ikcp_input(kcpobj, ackbuf, recvLen);
        }
        usleep(20);
    }
    printf("[send] over\n");
abort:
    (void)fclose(file);
}

/*
 * Receive a file.
 */
static void tftp_recvfile(const struct formats* pf, struct tftphdr* oap, int oacklen)
{
    struct tftphdr* dp;
    int size;
    /* These are "static" to avoid longjmp funnies */
    static u_short block = 0;
    static int acksize;
    u_short dp_opcode, dp_block;
    int recvLen = 0;
    int kcpRecv = 0;
    socklen_t fromlen;

    if (!block && oap)
    {
        acksize = oacklen;
        if (ikcp_send(kcpobj, (char*)oap, oacklen) < 0)
        {
            syslog(LOG_WARNING, "tftpd: write(ack): %m");
            goto abort;
        }
        ikcp_update(kcpobj, iclock());
    }

    dp = w_init();
    do
    {
    recv:
        ikcp_update(kcpobj, iclock());
        if (kcpobj->state == (IUINT32)-1)
        {
            syslog(LOG_ERR, "network timeout \n");
            printf("network timeout \n");
            goto abort;
        }
        kcpRecv = ikcp_recv(kcpobj, (char*)dp, MAX_SEGSIZE + 4);
        while (kcpRecv > 0)
        {
            dp_opcode = ntohs((u_short)dp->th_opcode);
            dp_block  = ntohs((u_short)dp->th_block);
            if (dp_opcode == ERROR)
                goto abort;
            if (dp_opcode == DATA)
            {
                if (!++block)
                    block = g_rollover_val;
                printf("received block：%d and write block:%d\n", dp_block, block);
                write_behind(file, pf->f_convert);
                /*  size = write(file, dp->th_data, n - 4); */
                size = writeit(file, &dp, kcpRecv - 4, pf->f_convert);
                if (size != (kcpRecv - 4))
                { /* ahem */
                    if (size < 0)
                        nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, errno + 100, NULL);
                    else
                        nak(PROTOCOL_KCP, MESSAGE_TYPE_ERROR, ENOSPACE, NULL);
                    goto abort;
                }

                if (size != segsize)
                {
                    goto end;
                }
            }

            kcpRecv = ikcp_recv(kcpobj, (char*)dp, MAX_SEGSIZE + 4);
        }

        fromlen = sizeof(from);
        recvLen = recvfrom(g_peer, dp, MAX_SEGSIZE + 4, MSG_DONTWAIT, &from.sa, &fromlen);
        if (recvLen > 0)
        {
            ikcp_input(kcpobj, dp, recvLen);
            usleep(1000);
            goto recv;
        }
        else
        {
            usleep(1000);
            goto recv;
        }

    } while (size == segsize);
end:
    ikcp_update(kcpobj, iclock());
    ikcp_flush(kcpobj);
    while (!iqueue_is_empty(&kcpobj->snd_buf) || !iqueue_is_empty(&kcpobj->rcv_buf))
    {
        ikcp_update(kcpobj, iclock());
        recvLen = recvfrom(g_peer, dp, MAX_SEGSIZE + 4, MSG_DONTWAIT, &from.sa, &fromlen);
        if (recvLen > 0)
        {
            ikcp_input(kcpobj, (char*)dp, recvLen);
        }
        usleep(20);
    }
    printf("[recv] over\n");
    write_behind(file, pf->f_convert);
    (void)fclose(file); /* close data file */
abort:
    return;
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
static void nak(int kcp, int type, int error, const char* msg)
{
    struct tftphdr* tp;
    int length;

    tp = (struct tftphdr*)g_buf;
    if (type == MESSAGE_TYPE_ERROR)
    {
        tp->th_opcode = htons((u_short)ERROR);
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
    }
    else if (type == MESSAGE_TYPE_RETURN)
    {
        tp->th_opcode = htons((u_short)RETURN);
    }

    tp->th_code = htons((u_short)error);

    length = strlen(msg) + 1;
    memcpy(tp->th_msg, msg, length);
    length += 4; /* Add space for header */

    if (g_verbosity >= 2)
    {
        tmp_p = (char*)inet_ntop(from.sa.sa_family, SOCKADDR_P(&from), tmpbuf, INET6_ADDRSTRLEN);
        if (!tmp_p)
        {
            tmp_p = tmpbuf;
            strcpy(tmpbuf, "???");
        }
        syslog(LOG_INFO, "sending NAK (%d, %s) to %s", error, tp->th_msg, tmp_p);
    }

    if (kcp)
    {
        if (ikcp_send(kcpobj, g_buf, length) < 0)
            syslog(LOG_WARNING, "nak: %m");
        ikcp_update(kcpobj, iclock);
    }
    else
    {
        if (send(g_peer, g_buf, length, 0) != length)
            syslog(LOG_WARNING, "nak: %m");
    }
}

ikcpcb* kcp_init(struct kcp_context* ctx)
{
    kcpobj = ikcp_create(123, ctx);
    ikcp_wndsize(kcpobj, 1024, 1024);
    ikcp_nodelay(kcpobj, 1, 20, 2, 1);
    ikcp_setoutput(kcpobj, kcp_op);
    ikcp_update(kcpobj, iclock());

    return kcpobj;
}

void kcp_uninit(ikcpcb* obj)
{
    ikcp_flush(obj);
    ikcp_release(obj);
}

int kcp_op(const char* buf, int len, ikcpcb* kcp, void* user)
{
    struct kcp_context* ctx = (struct kcp_context*)user;
    printf("Send %d bytes\n", len);
    return sendto(ctx->socket, buf, len, 0, &ctx->peeraddr.sa, SOCKLEN(&ctx->peeraddr));
}
