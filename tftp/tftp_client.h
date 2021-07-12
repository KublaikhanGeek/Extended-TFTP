/*
 * Copyright (c) 1993
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

#ifndef TFTP_CLIENT_H
#define TFTP_CLIENT_H

// obj
void* tftp_create(const char* serverip, int port, const char* localip, int localport);
void tftp_destroy(void* obj);

// setting
int tftp_set_server(void* obj, const char* serverip, int port);
int tftp_set_mode(void* obj, const char* mode); // set file transfer mode: "netascii", "octet"
int tftp_set_verbose(void* obj, int onoff);     // toggle verbose mode
int tftp_set_trace(void* obj, int onoff);       // toggle packet tracing
int tftp_set_literal(void* obj, int onoff);     // toggle literal mode, ignore ':' in file name
int tftp_set_rexmt(void* obj, int rexmt);       // set per-packet transmission timeout
int tftp_set_timeout(void* obj, int timeout);   // set total retransmission timeout

// cmd
int tftp_cmd_get(void* obj, const char* local, const char* remote, int* remotesize, int* transfersize); // receive file
int tftp_cmd_put(void* obj, const char* local, const char* remote, int* localsize, int* transfersize);  // send file
int tftp_cmd_cd(void* obj, const char* path);
int tftp_cmd_cdup(void* obj);
int tftp_cmd_lcd(void* obj, const char* path);
int tftp_cmd_pwd(void* obj, char* pwd);
int tftp_cmd_delete(void* obj, const char* path);
int tftp_cmd_ls(void* obj, char* buf);
int tftp_cmd_dir(void* obj, char* buf);
int tftp_cmd_mkdir(void* obj, const char* path);
int tftp_cmd_rmdir(void* obj, const char* path);
int tftp_cmd_size(void* obj, const char* path, int* size);
int tftp_cmd_chmod(void* obj, const char* path, const char* mode);

#endif
