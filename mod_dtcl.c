/* Copyright David Welton 1998, 1999 */

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* $Id$  */

/* http_dtcl.c by David Welton <davidw@efn.org> - originally mod_include.  */
/* Changes, improvements and bugfixes by Rolf Ade, Paolo Brutti and Patrick Diamond. */
/* Windows stuff by Jan Nijtmans. */

/*
 * http_include.c: Handles the server-parsed HTML documents
 *
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Apache module framework by rst.
 *
 */

/* This is an Apache hack to get the module to compile against libtcl. */

/*
 * MODULE-DEFINITION-START
 * Name: dtcl_module
 * ConfigStart
    LIBS="$LIBS -ltcl -ldl"
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

#include "http_conf_globals.h"

#include <tcl.h>
#include <string.h>

/* Error wrappers  */
#define ER1 "<hr><p><code><pre>\n"
#define ER2 "</pre></code><hr>\n"

/* Enable debugging */
#define DBG 0

/* Configuration options  */

/* If you do not have a threaded Tcl, you can define this to 0.  This
   has the effect of running Tcl Init code in the main parent init
   handler, instead of in child init handlers. */
#ifdef __MINGW32__
#define THREADED_TCL 1
#else 
#define THREADED_TCL 0 /* Unless you have MINGW32, modify this one! */
#endif

/* Turn on the translation stuff.  This will translate things to UTF
   correctly.  Turn off *only* if you will *not* use anything but
   plain ascii */

#define DTCL_I18N 1

/* End Configuration options  */

#define STARTING_SEQUENCE "<+"
#define ENDING_SEQUENCE "+>"
#define DEFAULT_ERROR_MSG "[an error occurred while processing this directive]"
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#define DEFAULT_HEADER_TYPE "text/html"
#define DTCL_VERSION "0.8.5"

/* *** Global variables *** */
static Tcl_Interp *interp;              /* Tcl interpreter */
static request_rec *global_rr;		/* request rec */
static Tcl_Encoding system_encoding;    /* Default encoding  */

/* output buffer for initial buffer_add. We use traditional memory
   management stuff on obuff - malloc, free, etc., because I couldn't
   get it to work well with the apache functions - davidw */

typedef struct {
    char *buf;
    int len;
} obuff;

static obuff obuffer = {
    NULL,
    0
};

static Tcl_Obj *namespacePrologue;      /* initial bit of Tcl for namespace creation */
module MODULE_VAR_EXPORT dtcl_module;

static char **objCacheList; 		/* Array of cached objects (for priority handling) */
static Tcl_HashTable objCache; 		/* Objects cache - the key is the script name */

static int buffer_output = 0;           /* Start with output buffering off */
static int headers_printed = 0; 	/* has the header been printed yet? */
static int headers_set = 0; 	        /* has the header been set yet? */
static int content_sent = 0;            /* make sure something gets sent */

static int cacheSize = 0;               /* size of cache, determined
                                           either in conf files, or
                                           set to
                                           "ap_max_requests_per_child
                                           / 2"; in the
                                           dtcl_init_handler function */
static int cacheFreeSize = 0;           /* free space in cache */


/* Functions for Tcl Channel */
/*
static int closeproc(ClientData, Tcl_Interp *);
static int inputproc(ClientData, char *, int, int *);
*/
static int outputproc(ClientData, char *, int, int *);
/*
static int setoptionproc(ClientData, Tcl_Interp *, char *, char *);
static int getoptionproc(ClientData, Tcl_Interp *, char *, Tcl_DString *);
static void watchproc(ClientData, int);
*/
/* Apache BUFF Channel Type */
static Tcl_ChannelType Achan = {
    "apache_channel",
    NULL,
    NULL,
    NULL,
    outputproc,
    NULL,
    NULL,
    NULL,
    NULL,
#if TCL_MINOR_VERSION >= 2
    NULL,
    NULL
#else
    NULL
#endif
};

/* just need some arbitrary non-NULL pointer which can't also be a request_rec */
#define NESTED_INCLUDE_MAGIC	(&dtcl_module)

static int memwrite(obuff *, char *, int);
static int parseargs(char *, request_rec *);
static int send_content(request_rec *);
static int send_parsed_file(request_rec *, char *, struct stat*, int);
static int send_tcl_file(request_rec *, char *, struct stat*);
static int set_header_type(request_rec *, char *);
static int print_headers(request_rec *);
static int print_error(request_rec *, int, char *);
static int flush_output_buffer(request_rec *);
static void tcl_init_stuff(server_rec *s, pool *p);

/*
int closeproc(ClientData instancedata, Tcl_Interp *interp)
{
    return TCL_OK;
}

int inputproc(ClientData instancedata, char *buf, int toRead, int *errorCodePtr)
{
    return TCL_OK;
}
*/

/* This is the output 'method' for the Memory Buffer Tcl 'File'
   Channel that we create to divert stdout to */

static int outputproc(ClientData instancedata, char *buf, int toWrite, int *errorCodePtr)
{
    memwrite(&obuffer, buf, toWrite);
    return toWrite;		
} 

/* int setoptionproc(ClientData instancedata, Tcl_Interp *interp,
				      char *optionname, char *value)
{
    return TCL_OK;
}

int getoptionproc(ClientData instancedata, Tcl_Interp *intepr,
				      char *optionname, Tcl_DString *dsPtr)
{
    return TCL_OK;
}

void  watchproc(ClientData instancedata, int mask)
{
    return;
}
*/

/* Write something to the output buffer structure */

static int memwrite(obuff *buffer, char *input, int len)
{
    if (buffer->len == 0)
    {
	buffer->buf = Tcl_Alloc(len + 1);
	memcpy(buffer->buf, input, len);
	buffer->buf[len] = '\0';
	buffer->len = len;
    }
    else
    {
	char *bufend;
	buffer->buf = Tcl_Realloc(buffer->buf, len + buffer->len + 1);
	bufend = buffer->buf + buffer->len;
	memmove(bufend, input, len);
	buffer->buf[len + buffer->len] = '\0';
	buffer->len += len;
    }
    return len;
}

/* Set up the content type header */

static int set_header_type(request_rec *r, char *header)
{
    if (headers_set == 0)
    {
	r->content_type = header;
	headers_set = 1;
	return 1;
    } else {
	return 0;
    }
}

/* Printer headers if they haven't been printed yet */

static int print_headers(request_rec *r)
{
    if (headers_printed == 0)
    {
	if (headers_set == 0)
	    set_header_type(r, DEFAULT_HEADER_TYPE);

	ap_send_http_header(global_rr);
	headers_printed = 1;
	return 1;
    } else {
	return 0;
    }
}

/* Print nice HTML formatted errors */

static int print_error(request_rec *r, int htmlflag, char *errstr)
{
    int j;

    set_header_type(r, DEFAULT_HEADER_TYPE);
    print_headers(r);

    if (htmlflag != 1)
	ap_rputs(ER1, r);

    if (errstr != NULL)
    {
	if (htmlflag != 1)
	{
	    int ln = strlen(errstr);
	    for (j = 0; j < ln; j++)
	    {
		if (errstr[j] == '<')
		{
		    ap_rwrite("&lt;", 4, r);
		}  else if (errstr[j] == '>') {
		    ap_rwrite("&gt;", 4, r);
		} else { 
		    ap_rwrite((errstr+j), 1, r);
		}
	    }
	} else {
	    ap_rputs(errstr, global_rr);  	
	}
    }    
    if (htmlflag != 1)
	ap_rputs(ER2, r);

    return 0;
}

/* Make sure that everything in the output buffer has been flushed,
   and that headers have been printed */

static int flush_output_buffer(request_rec *r)
{
    print_headers(r);
    if (obuffer.len != 0)
    {
	ap_rwrite(obuffer.buf, obuffer.len, r);
	free(obuffer.buf);
	obuffer.len = 0;
	obuffer.buf = NULL;
    }
    content_sent = 1;
    return 0;
}

/* Taken from PHP3 */
/* mime encode a string */

static char *cgiEncodeObj (Tcl_Obj *sObj)
{
    unsigned char hexchars[] = "0123456789ABCDEF";
    register int x, y;
    unsigned char *str;
    char *s;
    int len;

    s = Tcl_GetStringFromObj(sObj, &len);
    str = (unsigned char *) ap_palloc(global_rr->pool, 3 * len + 1);
    for (x = 0, y = 0; len--; x++, y++)
    {
	str[y] = (unsigned char) s[x];
	if (str[y] == ' ')
	{
	    str[y] = '+';
	} else if ((str[y] < '0' && str[y] != '-' && str[y] != '.') ||
		   (str[y] < 'A' && str[y] > '9') ||
		   (str[y] > 'Z' && str[y] < 'a' && str[y] != '_') ||
		   (str[y] > 'z'))
	{
	    str[y++] = '%';
	    str[y++] = hexchars[(unsigned char) s[x] >> 4];
	    str[y] = hexchars[(unsigned char) s[x] & 15];
	}
    }
    str[y] = '\0';
    return ((char *) str);
}

/* more stuff from PHP - used in cgiDecodeString*/

static int php3_htoi(char *s)
{
    int value;
    int c;
    
    c = s[0];
    if (isupper(c))
	c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
    
    c = s[1];
    if (isupper(c))
	c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
    
    return (value);
}

/* This is from PHP too.  I don't like to reinvent the wheel:-) -
   davidw */

static char *cgiDecodeString (char *text)
{
    int len = 0;
    char *dest = text;
    char *data = text;

    len = strlen(text);

    while (len--) {
	if (*data == '+')
	    *dest = ' ';
	else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2))) {
	    *dest = (char) php3_htoi(data + 1);
	    data += 2;
	    len -= 2;
	} else
	    *dest = *data;
	data++;
	dest++;
    }
    *dest = '\0';
    return text;
}

/* Function to convert strings to UTF encoding */

static char *StringToUtf(char *input)
{
#if DTCL_I18N == 1
    char *temp;
    Tcl_DString dstr;
    Tcl_DStringInit(&dstr);
    Tcl_ExternalToUtfDString(system_encoding, input, strlen(input), &dstr);

    temp = ap_pstrdup(global_rr->pool, Tcl_DStringValue(&dstr));
    Tcl_DStringFree(&dstr);
    return temp;
#else
    /* If we aren't using the i18n stuff, no need to do anything */
    return input;
#endif
}

/* Include and parse a file */

static int Parse(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *filename;
    struct stat finfo;

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "filename");
	return TCL_ERROR;
    }

    filename = Tcl_GetStringFromObj (objv[1], (int *)NULL);
    if (!strcmp(filename, global_rr->filename))
    {
	Tcl_AddErrorInfo(interp, "Cannot recursively call the same file!");
	return TCL_ERROR;
    }

    if (stat(filename, &finfo))
    {
	Tcl_AddErrorInfo(interp, Tcl_PosixError(interp));
	return TCL_ERROR;
    }
    if (send_parsed_file(global_rr, filename, &finfo, 0) == OK)
	return TCL_OK;
    else
	return TCL_ERROR;
}

/* Tcl command to include flat files */

static int Include(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Channel fd;
    int sz;
    char buf[2000];

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "filename");
	return TCL_ERROR;
    }

    fd = Tcl_OpenFileChannel(interp,
			     Tcl_GetStringFromObj (objv[1], (int *)NULL), "r", 0664);

    if (fd == NULL)
    {
        return TCL_ERROR;
    } else {
	Tcl_SetChannelOption(interp, fd, "-translation", "lf");
    }
    flush_output_buffer(global_rr);
    while ((sz = Tcl_Read(fd, buf, sizeof(buf) - 1)))
    {
	if (sz == -1)
	{
	    Tcl_AddErrorInfo(interp, Tcl_PosixError(interp));
	    return TCL_ERROR;
	}

	buf[sz] = '\0';
	memwrite(&obuffer, buf, sz);

/*   	ap_rwrite(buf, sz, global_rr);   */

	if (sz < sizeof(buf) - 1)
	    break;
    }
    return Tcl_Close(interp,fd);

/*     close(fd);  */
    return TCL_OK;
}

/* Command to *only* add to the output buffer */

static int Buffer_Add(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *arg1;
    int len;
    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	return TCL_ERROR;
    }
    arg1 = Tcl_GetByteArrayFromObj(objv[1], &len);

    memwrite(&obuffer, arg1, len);
    content_sent = 0;
    return TCL_OK;
}

/* Tcl command to output some text to the web server  */

static int Hputs(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *arg1;
    int length;
    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	return TCL_ERROR;
    }

    arg1 = Tcl_GetByteArrayFromObj(objv[1], &length);

    if (!strncmp("-error", arg1, 6))
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	    return TCL_ERROR;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, global_rr->server, "Mod_Dtcl Error: %s", Tcl_GetStringFromObj (objv[2], (int *)NULL));
    } else {
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	    return TCL_ERROR;
	}
    }

    if (buffer_output == 1)
    {
	memwrite(&obuffer, arg1, length);
    } else {
	flush_output_buffer(global_rr);
	ap_rwrite(arg1, length, global_rr);
    }

    return TCL_OK;
}

/* Tcl command to manipulate headers */

static int Headers(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *opt;
    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "headers option arg ?arg ...?");
	return TCL_ERROR;
    }
    if (headers_printed != 0)
    {
	print_error(global_rr, 0, "Cannot manipulate headers - already sent");
	return TCL_ERROR;
    }
    opt = Tcl_GetStringFromObj(objv[1], NULL);

    if (!strcmp("setcookie", opt)) /* ### setcookie ### */
    {
	char *cookie;
	int i, idx;
	static char* cookieParms[] = {
	    "-expires", "-domain", "-path", "-secure", NULL
	};
	static char* cookieStrings[] = {
	    "; expires=", "; domain=", "; path=", "; secure"
	};

	if (objc < 4 || objc > 10)
	{
	    Tcl_WrongNumArgs(interp, 1, objv,
			     "setcookie cookie-name cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure?");
	    return TCL_ERROR;
	}

	/* SetCookie: foo=bar; EXPIRES=DD-Mon-YY HH:MM:SS; DOMAIN=domain; PATH=path; SECURE */
	if (*(Tcl_GetStringFromObj(objv[3], NULL)))
	{
	    cookie = ap_pstrcat(global_rr->pool, cgiEncodeObj(objv[2]), "=",
                          cgiEncodeObj(objv[3]), NULL);
	} else {
	    cookie = cgiEncodeObj(objv[2]);
	}

	for (i = 4; i < objc; i++)
	{
	    if (Tcl_GetIndexFromObj(interp, objv[i], cookieParms, "option", 0, &idx) != TCL_OK)
	    {
		return TCL_ERROR;
	    } else if (idx == 4) {
		cookie = ap_pstrcat(global_rr->pool, cookie, cookieStrings[idx], NULL);
	    } else if (++i >= objc) {
		Tcl_WrongNumArgs(interp, 1, objv,
				 "setcookie cookie-name cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure?");
		return TCL_ERROR;
	    } else {
		cookie = ap_pstrcat(global_rr->pool, cookie, cookieStrings[idx],
				    cgiEncodeObj(objv[i]), NULL);
	    }
	}
	ap_table_add(global_rr->headers_out, "Set-Cookie", cookie);
    }
    else if (!strcmp("redirect", opt)) /* ### redirect ### */
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "headers redirect new-url");
	    return TCL_ERROR;
	}
	ap_table_set(global_rr->headers_out, "Location", Tcl_GetStringFromObj (objv[2], (int *)NULL));
	global_rr->status = 301;
	ap_send_error_response(global_rr, 0); /* note that this is immediate XXX */
	return TCL_RETURN;
    }
    else if (!strcmp("set", opt)) /* ### set ### */
    {
	if (objc != 4)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "set headername value");
	    return TCL_ERROR;
	}
	ap_table_set(global_rr->headers_out,
		     Tcl_GetStringFromObj (objv[2], (int *)NULL),
		     Tcl_GetStringFromObj (objv[3], (int *)NULL));
    }
    else if (!strcmp("type", opt)) /* ### set ### */
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "type mime/type");
	    return TCL_ERROR;
	}
	set_header_type(global_rr, Tcl_GetStringFromObj(objv[2], (int *)NULL));
    } else {
	// XXX	Tcl_WrongNumArgs(interp, 1, objv, "headers option arg ?arg ...?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/* turn buffering on and off */

static int Buffered(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *opt = Tcl_GetStringFromObj(objv[1], NULL);
    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "on/off");
	return TCL_ERROR;
    }
    if (!strncmp(opt, "on", 2))
    {
	buffer_output = 1;
    } else if (!strncmp(opt, "off", 3)) {
	buffer_output = 0;
    } else {
	return TCL_ERROR;
    }
    flush_output_buffer(global_rr);
    return TCL_OK;
}
/* Tcl command to flush the output stream */

static int HFlush(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    if (objc != 1)
    {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    flush_output_buffer(global_rr);
    ap_rflush(global_rr);
    return TCL_OK;
}

/* Tcl command to get and parse any CGI and environmental variables */

/* Get the environmental variables, but do it from a tcl function, so
   we can decide whether we wish to or not */

static int HGetVars(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *timefmt = DEFAULT_TIME_FORMAT;
#ifndef WIN32
    struct passwd *pw;
#endif /* ndef WIN32 */
    char *t;

    time_t date = global_rr->request_time;

    int i;

    array_header *hdrs_arr;
    table_entry *hdrs;
    array_header *env_arr;
    table_entry  *env;

    /* ensure that the system area which holds the cgi variables is empty */
    ap_clear_table(global_rr->subprocess_env);

    /* retrieve cgi variables */
    ap_add_cgi_vars(global_rr);
    ap_add_common_vars(global_rr);
    
    hdrs_arr = ap_table_elts(global_rr->headers_in);
    hdrs = (table_entry *) hdrs_arr->elts;
    
    env_arr =  ap_table_elts(global_rr->subprocess_env);
    env     = (table_entry *) env_arr->elts;

    /* These were the "include vars"  */
    Tcl_SetVar2(interp, "::request::ENVS", "DATE_LOCAL", StringToUtf(ap_ht_time(global_rr->pool, date, timefmt, 0)), 0);
    Tcl_SetVar2(interp, "::request::ENVS", "DATE_GMT", StringToUtf(ap_ht_time(global_rr->pool, date, timefmt, 1)), 0);
    Tcl_SetVar2(interp, "::request::ENVS", "LAST_MODIFIED", StringToUtf(ap_ht_time(global_rr->pool, global_rr->finfo.st_mtime, timefmt, 0)), 0);
    Tcl_SetVar2(interp, "::request::ENVS", "DOCUMENT_URI", StringToUtf(global_rr->uri), 0);
    Tcl_SetVar2(interp, "::request::ENVS", "DOCUMENT_PATH_INFO", StringToUtf(global_rr->path_info), 0);

#ifndef WIN32
    pw = getpwuid(global_rr->finfo.st_uid);
    if (pw)
	Tcl_SetVar2(interp, "::request::ENVS", "USER_NAME", StringToUtf(ap_pstrdup(global_rr->pool, pw->pw_name)), 0);
    else
	Tcl_SetVar2(interp, "::request::ENVS", "USER_NAME",
		    StringToUtf(ap_psprintf(global_rr->pool, "user#%lu", (unsigned long) global_rr->finfo.st_uid)), 0);
#endif

    if ((t = strrchr(global_rr->filename, '/')))
	Tcl_SetVar2(interp, "::request::ENVS", "DOCUMENT_NAME", StringToUtf(++t), 0);
    else
	Tcl_SetVar2(interp, "::request::ENVS", "DOCUMENT_NAME", StringToUtf(global_rr->uri), 0);

    if (global_rr->args)
    {
	char *arg_copy = ap_pstrdup(global_rr->pool, global_rr->args);
	ap_unescape_url(arg_copy);
	Tcl_SetVar2(interp, "::request::ENVS", "QUERY_STRING_UNESCAPED", StringToUtf(ap_escape_shell_cmd(global_rr->pool, arg_copy)), 0);
    }

    /* ----------------------------  */

    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
	if (!hdrs[i].key)
	    continue;
	/* turn cookies into variables  */
	if (!strncmp(hdrs[i].key, "Cookie", strlen("Cookie")))
	{
	    char *var;
	    char *val = NULL;
	    char *p = ap_pstrdup(global_rr->pool, hdrs[i].val);

	    var = strtok(p, ";");

	    while(var)
	    {
		val = strchr(var, '=');
		if (val)
		{
		    *val++ = '\0';
		    val = cgiDecodeString(val);
		}
		Tcl_SetVar2(interp, "::request::COOKIES", cgiDecodeString(var), val, 0);
		var = strtok(NULL, ";");
	    }
	} else {
	    Tcl_SetVar2(interp, "::request::ENVS", StringToUtf(hdrs[i].key), StringToUtf(hdrs[i].val), 0);
	}
    }

    /* transfer apache internal cgi variables to TCL request namespace */
    for (i = 0; i < env_arr->nelts; ++i)
    {
	if (!env[i].key)
	    continue;
	Tcl_SetVar2(interp, "::request::ENVS", StringToUtf(env[i].key), StringToUtf(env[i].val), 0);
    }

    /* cleanup system cgi variables */
    ap_clear_table(global_rr->subprocess_env);

    return TCL_OK;
}

/* Tcl command to get, and print some information about the current
   state of affairs */

static int Dtcl_Info(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *tble;
    tble = ap_psprintf(global_rr->pool,
		       "<table border=0 bgcolor=green><tr><td>\n"
		       "<table border=0 bgcolor=\"#000000\">\n"
		       "<tr><td align=center bgcolor=blue><font color=\"#ffffff\" size=+2>dtcl_info</font><br></td></tr>\n"
		       "<tr><td><font color=\"#ffffff\">Free cache size: %d</font><br></td></tr>\n"
		       "<tr><td><font color=\"#ffffff\">PID: %d</font><br></td></tr>\n"
		       "</table>\n"
		       "</td></tr></table>\n", cacheFreeSize, getpid());
    flush_output_buffer(global_rr);
    print_headers(global_rr);
    ap_rputs(tble, global_rr);
    return TCL_OK;
}

/* This function does the GET variables passed to us  */
static int parseargs(char *inargs, request_rec *r)
{
    char *line, *cp, *var = NULL, *val = NULL, *linept;

    int i, numargs;

    line = ap_pstrdup(r->pool, inargs);
    for (cp = line; *cp; cp++)
	if (*cp == '+')
	    *cp = ' ';

    if (strlen(line))
    {
	for (numargs = 1, cp = line; *cp; cp++)
	    if (*cp == '&') numargs++;
    } else
	numargs = 0;

    linept = line;
    for(i = 0; i < numargs; i ++)
    {
	cp = strchr(linept, '=');
	if (cp != NULL)
	{
	    var = ap_pstrndup(r->pool, linept, cp - linept);
	    linept = cp;
	    linept ++;

	    cp = strchr(linept, '&');
	    if (cp != NULL)
	    {
		val = ap_pstrndup(r->pool, linept, cp - linept);
		linept = cp;
		linept ++;
	    }
	    else
	    {
		val = ap_pstrdup(r->pool, linept);
	    }
	}
	else
	{
	    var = linept;
	    val = ap_pstrdup(r->pool, "");
	}

	/* This code has the effect of doing a join [ concat stuff
           stuff ].
	   This is necessary so that it is one big list without sublists.
	*/
	{
	    Tcl_Obj *vars = Tcl_NewStringObj("::request::VARS", -1);
	    Tcl_Obj *newval = Tcl_NewStringObj(StringToUtf(cgiDecodeString(val)), -1);
	    Tcl_Obj *newvar = Tcl_NewStringObj(StringToUtf(cgiDecodeString(var)), -1);
	    Tcl_Obj *oldvar = Tcl_ObjGetVar2(interp, vars, newvar, 0);

	    if (oldvar == NULL)
	    {
		Tcl_ObjSetVar2(interp, vars, newvar, newval, 0);
	    } else {
		Tcl_Obj *concat[2];
		concat[0] = oldvar;
		concat[1] = newval;
		Tcl_ObjSetVar2(interp, vars, newvar, Tcl_ConcatObj(2, concat), 0);
	    }
	}
    }

    return 0;
}

/* Load, cache and eval a Tcl file  */

static int send_tcl_file(request_rec *r, char *filename, struct stat *finfo)
{
#if 1
    /* Taken, in part, from tclIOUtil.c out of the Tcl
       distribution, and modified */

    /* Basically, what we are doing here is a Tcl_EvalFile, but
       with the addition of caching code. */
    int result;
    int isNew;

    char *hashKey;

    Tcl_HashEntry *entry;
    Tcl_Obj *cmdObjPtr;

    /* Look for the script's compiled version. If it's not found, create it. */
    hashKey = ap_psprintf(r->pool, "%s%ld%ld", r->filename, r->finfo.st_mtime, r->finfo.st_ctime);
    entry = Tcl_CreateHashEntry(&objCache, hashKey, &isNew);
    if (isNew || !cacheSize) {
	char *cmdBuffer = (char *) NULL;
	Tcl_Channel chan = Tcl_OpenFileChannel(interp, r->filename, "r", 0644);
	if (chan == (Tcl_Channel) NULL) 
	{
	    Tcl_ResetResult(interp);
	    Tcl_AppendResult(interp, "couldn't read file \"", r->filename,
			     "\": ", Tcl_PosixError(interp), (char *) NULL);
	    goto error;
	}

	cmdBuffer = (char *) malloc(r->finfo.st_size + 1);

	result = Tcl_Read(chan, cmdBuffer, r->finfo.st_size);
	if (result < 0) 
	{
	    Tcl_Close(interp, chan);
	    Tcl_AppendResult(interp, "couldn't read file \"", r->filename,
			     "\": ", Tcl_PosixError(interp), (char *) NULL);
	    goto error;
	}
	cmdBuffer[result] = 0;

	if (Tcl_Close(interp, chan) != TCL_OK) 
	    goto error;

	cmdObjPtr = Tcl_NewStringObj(cmdBuffer, result);
	Tcl_IncrRefCount(cmdObjPtr);
	Tcl_SetHashValue(entry, (ClientData)cmdObjPtr);
	free(cmdBuffer);

	if (cacheFreeSize) {
	    /* This MUST be malloc-ed, because it's permanent */
	    objCacheList[--cacheFreeSize ] = strdup(hashKey);
	} else if (cacheSize) { /* if it's zero, we just skip this... */
	    Tcl_HashEntry *delEntry;		
	    delEntry = Tcl_FindHashEntry(&objCache, objCacheList[cacheSize - 1]);
	    Tcl_DecrRefCount((Tcl_Obj *)Tcl_GetHashValue(delEntry));
	    Tcl_DeleteHashEntry(delEntry);
	    free(objCacheList[cacheSize - 1]);
	    memmove(objCacheList + 1, objCacheList, sizeof(char *)*(cacheSize -1));
	    objCacheList[0] = strdup(hashKey);
	}
	    
	/* yuck  */
	goto end;
    error:
	if (cmdBuffer != (char *) NULL) {
	    free(cmdBuffer);
	}
	return TCL_ERROR;	
	    
    end:
	Tcl_EvalObj(interp, (cmdObjPtr));
    } else {
	Tcl_EvalObj(interp, (Tcl_Obj *)Tcl_GetHashValue(entry));
    }
#else
    Tcl_EvalFile(interp, r->filename);
#endif
    flush_output_buffer(global_rr);

    return OK;
}

/* Parse and execute a ttml file */

static int send_parsed_file(request_rec *r, char *filename, struct stat *finfo, int toplevel)
{
    char *errorinfo;
    char *hashKey;
    Tcl_Obj *outbuf;
    int isNew;
    Tcl_HashEntry *entry;

    /* Look for the script's compiled version. If it's not found, create it. */
    hashKey = ap_psprintf(r->pool, "%s%ld%ld%d", filename, finfo->st_mtime, finfo->st_ctime, toplevel);
    entry = Tcl_CreateHashEntry(&objCache, hashKey, &isNew);
    if (isNew || !cacheSize) {
	/* BEGIN PARSER  */
	char inside = 0;	/* are we inside the starting/ending delimiters  */

	const char *strstart = STARTING_SEQUENCE;
	const char *strend = ENDING_SEQUENCE;

	char c;
	int ch;
	int l = strlen(ENDING_SEQUENCE), l2 = strlen(STARTING_SEQUENCE), p = 0;

	FILE *f = NULL;

	if (!(f = ap_pfopen(r->pool, filename, "r")))
	{
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "file permissions deny server access: %s", filename);
	    return HTTP_FORBIDDEN;
	}

	/* Beginning of the file parser */
	if (toplevel)
	    outbuf = Tcl_NewStringObj("namespace eval request { buffer_add \"", -1);
	else
	    outbuf = Tcl_NewStringObj("hputs \"\n", -1);

	while ((ch = getc(f)) != EOF)
	{
	    /* ok, if we find the string, then we start on another loop    */
	    /*            if (!find_string(f, STARTING_SEQUENCE, r))  */
	    if (!inside)
	    {
		/* OUTSIDE  */
		if (ch == -1)
		    if (ferror(f))
		    {
			ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
				     "Encountered error in mod_dtcl getchar routine while reading %s",
				     r->uri);
			ap_pfclose( r->pool, f);
		    }
		c = ch;
		if (c == strstart[p])
		{
		    if (( ++p ) == l)
		    {
			/* ok, we have matched the whole ending sequence - do something  */
			Tcl_AppendToObj(outbuf, "\"\n", 2);
			inside = 1;
			p = 0;
			continue;
		    }
		} else {
		    Tcl_AppendToObj(outbuf, (char *)strstart, p);
		    /* or else just put the char in outbuf  */
		    if (c == '$')
			Tcl_AppendToObj(outbuf, "\\$", -1);
		    else if ( c == '[')
			Tcl_AppendToObj(outbuf, "\\[", -1);
		    else if ( c == ']')
			Tcl_AppendToObj(outbuf, "\\]", -1);
		    else if ( c == '"')
			Tcl_AppendToObj(outbuf, "\\\"", -1);
		    else if ( c == '\\')
			Tcl_AppendToObj(outbuf, "\\\\", -1);
		    else
			Tcl_AppendToObj(outbuf, &c, 1);

		    p = 0;
		    continue;
		}
	    } else {
		/* INSIDE  */
		if (ch == -1)
		    if (ferror(f))
		    {
			ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
				     "Encountered error in mod_dtcl getchar routine while reading %s",
				     r->uri);
			ap_pfclose( r->pool, f);
			return DONE;
		    }

		c  = ch;

		if (c == strend[p])
		{
		    if ((++p) == l2)
		    {
			inside = 0;
			Tcl_AppendToObj(outbuf, "\n hputs \"", -1);
			p = 0;
			continue;
		    }
		}
		else
		{
		    /*  plop stuff into outbuf, which we will then eval   */
		    Tcl_AppendToObj(outbuf, (char *)strend, p);
		    Tcl_AppendToObj(outbuf, &c, 1);
		    p = 0;
		}
	    }
	}
	ap_pfclose(r->pool, f);

	if (!inside)
	{
	    Tcl_AppendToObj(outbuf, "\"", 1);
	}

	if (toplevel)
	    Tcl_AppendToObj(outbuf, "\n}\nnamespace delete request\n", -1);
	else
	    Tcl_AppendToObj(outbuf, "\n", -1);

	Tcl_IncrRefCount(outbuf);

#if DTCL_I18N == 1
	/* Convert to encoding  */
	Tcl_SetStringObj(outbuf, StringToUtf(Tcl_GetString(outbuf)), -1);
#endif

	Tcl_SetHashValue(entry, (ClientData)outbuf);

	if (cacheFreeSize) {
	    /* This MUST be malloc-ed, because it's permanent */
	    objCacheList[--cacheFreeSize ] = strdup(hashKey);
	} else if (cacheSize) { /* if it's zero, we just skip this... */
	    Tcl_HashEntry *delEntry;

	    delEntry = Tcl_FindHashEntry(&objCache, objCacheList[cacheSize - 1]);
	    Tcl_DecrRefCount((Tcl_Obj *)Tcl_GetHashValue(delEntry));
	    Tcl_DeleteHashEntry(delEntry);
	    free(objCacheList[cacheSize - 1]);
	    memmove(objCacheList + 1, objCacheList, sizeof(char *)*(cacheSize -1));
	    objCacheList[0] = strdup(hashKey);
	}
	/* END PARSER  */
    } else {
	/* used the cached version */
        outbuf = (Tcl_Obj *)Tcl_GetHashValue(entry);
    }

#if DBG
    print_error(r, 0,
		Tcl_GetStringFromObj(outbuf, (int *)NULL));
    return OK;
#endif

    if (Tcl_EvalObj(interp, outbuf) == TCL_ERROR)
    {
	flush_output_buffer(global_rr);
	errorinfo = Tcl_GetVar(interp, "errorInfo", 0);
	print_error(r, 0, errorinfo);
	print_error(r, 1, "<p><b>OUTPUT BUFFER:</b></p>");
	print_error(r, 0, Tcl_GetStringFromObj(outbuf, (int *)NULL));
		    
/* 		    "</pre><b>OUTPUT BUFFER</b><pre>\n",
		    Tcl_GetStringFromObj(outbuf, (int *)NULL));  */
    } else {
	/* XXX we make sure to flush the output if buffer_add was the only output */
	flush_output_buffer(global_rr);
    }
    return OK;
}

/* Set things up to execute a file, then execute */

static int send_content(request_rec *r)
{
    char error[MAX_STRING_LEN];
    char timefmt[MAX_STRING_LEN];

    int rslt = 0;
    int errstatus;

    global_rr = r;		/* Assign request to global request var */

    r->allowed |= (1 << M_GET);
    r->allowed |= (1 << M_POST);
    if (r->method_number != M_GET && r->method_number != M_POST)
	return DECLINED;

    if (r->finfo.st_mode == 0)
    {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		     "File does not exist: %s",
		     (r->path_info
		      ? ap_pstrcat(r->pool, r->filename, r->path_info, NULL)
		      : r->filename));
	return HTTP_NOT_FOUND;
    }

    if ((errstatus = ap_meets_conditions(r)) != OK)
	return errstatus;

    /* We need to send it as html */
    /*     r->content_type = DEFAULT_HEADER_TYPE;  */

    if (r->header_only)
    {
	set_header_type(r, DEFAULT_HEADER_TYPE);
	print_headers(r);

	return OK;
    }

    ap_hard_timeout("send DTCL", r);

    /* xxx  */

    ap_cpystrn(error, DEFAULT_ERROR_MSG, sizeof(error));
    ap_cpystrn(timefmt, DEFAULT_TIME_FORMAT, sizeof(timefmt));
    ap_chdir_file(r->filename);

    if (Tcl_EvalObj(interp, namespacePrologue) == TCL_ERROR)
    {
	ap_log_error(APLOG_MARK, APLOG_ERR, r->server, "Could not create request namespace\n");
	exit(1);
    }
    if (r->args)
	rslt = parseargs(r->args, r);

    if (rslt)
    {
	print_error(r, 0, r->args);
	return DONE;
    }

    /* this gets the request body, from POST's, mostly, if I understand correctly */
    if ((rslt = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
	return DECLINED;

    /* this bit is for POST requests, more or less */
    /* I took it from mod_cgi and modified it to suit my needs */
    if (ap_should_client_block(r))
    {
	int len_read;
	char argsbuffer[HUGE_STRING_LEN + 1];
	char *argscumulative = NULL;

	ap_hard_timeout("copy script args", r);

	while ((len_read = ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0)
	{
	    argsbuffer[len_read] = '\0';
	    ap_reset_timeout(r);

	    if (argscumulative != NULL)
		argscumulative = ap_pstrcat(r->pool, argscumulative, argsbuffer, NULL);
	    else
		argscumulative = ap_pstrdup(r->pool, argsbuffer);
	}

	rslt = parseargs(argscumulative, r);
	if (rslt)
	{
	    print_error(r, 0, argscumulative);
	    return DONE;
	}
	ap_kill_timeout(r);
    }

    if(!strcmp(r->content_type, "application/x-httpd-tcl"))
    { 
	/* It's a TTML file  */
	send_parsed_file(r, r->filename, &(r->finfo), 1);
    } else { 	
	/* It's a plain Tcl file */
	send_tcl_file(r, r->filename, &(r->finfo));
    }

    /* reset globals  */
    buffer_output = 0;
    headers_printed = 0;
    headers_set = 0;
    content_sent = 0;

    ap_kill_timeout(r);
    return OK;
}

typedef struct {
    char *dtcl_global_script;
    char *dtcl_init_script;
    char *dtcl_exit_script;
    int dtcl_cache_size;
} dtcl_server_conf;

static void tcl_init_stuff(server_rec *s, pool *p)
{
    int rslt;
    void *sconf = s->module_config;  /* get module configuration */

    Tcl_Channel achan;

    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(sconf, &dtcl_module);

    /* Initialize TCL stuff  */

    /* Create TCL commands to deal with Apache's BUFFs. */

    interp = Tcl_CreateInterp();
    achan = Tcl_CreateChannel(&Achan, "apacheout", NULL, TCL_WRITABLE);

    system_encoding = Tcl_GetEncoding(NULL, "iso8859-1"); /* FIXME */


    Tcl_SetStdChannel(achan, TCL_STDOUT);
    Tcl_SetChannelOption(interp, achan, "-buffering", "none");

    Tcl_RegisterChannel(interp, achan);
    if (interp == NULL)
    {
	ap_log_error(APLOG_MARK, APLOG_ERR, s, "Error in Tcl_CreateInterp, aborting\n");
	exit(1);
    }
#if (TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION > 0)
    Tcl_FindExecutable(""); /* Needed for locating init.tcl */
#endif

    if (Tcl_Init(interp) == TCL_ERROR)
    {
	ap_log_error(APLOG_MARK, APLOG_ERR, s, Tcl_GetStringResult(interp));
	exit(1);
    }
    Tcl_CreateObjCommand(interp, "hputs", Hputs, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "buffer_add", Buffer_Add, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "buffered", Buffered, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "headers", Headers, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "hgetvars", HGetVars, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "include", Include, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "parse", Parse, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "hflush", HFlush, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "dtcl_info", Dtcl_Info, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

    namespacePrologue = Tcl_NewStringObj(
	"catch { namespace delete request }\n"
	"namespace eval request { }\n"
	"proc ::request::global { args } { foreach arg $args { uplevel \"::global ::request::$arg\" } }\n", -1);
    Tcl_IncrRefCount(namespacePrologue);

#if DBG
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Config string = \"%s\"", dsc->dtcl_global_script);  /* XXX */
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Cache size = \"%d\"", dsc->dtcl_cache_size);  /* XXX */
#endif

    if (dsc->dtcl_global_script != NULL)
    {
	rslt = Tcl_EvalFile(interp, dsc->dtcl_global_script);
	if (rslt != TCL_OK)
	{
	    ap_log_error(APLOG_MARK, APLOG_ERR, s, "%s",
			 Tcl_GetVar(interp, "errorInfo", 0));
	}
    }
    if (dsc->dtcl_cache_size != 0)
    {
	cacheSize = dsc->dtcl_cache_size;
	cacheFreeSize = dsc->dtcl_cache_size;
    } else {
	if (ap_max_requests_per_child != 0)
	    cacheSize = ap_max_requests_per_child / 2;
	else
	    cacheSize = 50; /* Arbitrary number */
	cacheFreeSize = cacheSize;
    }
    /* Initializing cache structures */
    objCacheList = malloc(cacheSize * sizeof(char *));
    Tcl_InitHashTable(&objCache, TCL_STRING_KEYS);
}

void dtcl_init_handler(server_rec *s, pool *p)
{
#if THREADED_TCL == 0
    tcl_init_stuff(s, p);
#endif
    ap_add_version_component("Mod_dtcl " DTCL_VERSION);
}

static const char *set_globalscript(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *conf = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    conf->dtcl_global_script = arg;
    return NULL;
}

static const char *set_initscript(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *conf = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    conf->dtcl_init_script = arg;
    return NULL;
}

static const char *set_exitscript(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *conf = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    conf->dtcl_exit_script = arg;
    return NULL;
}

static const char *set_cachesize(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *conf = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    conf->dtcl_cache_size = strtol(arg, NULL, 10);
    return NULL;
}

static void *create_dtcl_config(pool *p, server_rec *s)
{
    dtcl_server_conf *dts = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));
    dts->dtcl_global_script = NULL;
    dts->dtcl_init_script = NULL;
    dts->dtcl_exit_script = NULL;
    return dts;
}

static void *merge_dtcl_config(pool *p, void *basev, void *overridesv)
{
    dtcl_server_conf *base = (dtcl_server_conf *) basev, *overrides = (dtcl_server_conf *) overridesv;
    return overrides->dtcl_global_script ? overrides : base;
}


static void dtcl_child_init(server_rec *s, pool *p)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(s->module_config, &dtcl_module);

#if THREADED_TCL == 1
    tcl_init_stuff(s, p);
#endif

    if (dsc->dtcl_init_script != NULL)
	if (Tcl_EvalFile(interp, dsc->dtcl_init_script) != TCL_OK)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "Problem running child init script: %s", dsc->dtcl_init_script);
}

static void dtcl_child_exit(server_rec *s, pool *p)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(s->module_config, &dtcl_module);

    if (dsc->dtcl_exit_script != NULL)
	if (Tcl_EvalFile(interp, dsc->dtcl_exit_script) != TCL_OK)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "Problem running child exit script: %s", dsc->dtcl_exit_script);
}

static const handler_rec dtcl_handlers[] =
{
    {"application/x-httpd-tcl", send_content},
    {"text/x-tcl", send_content},
    {NULL}
};

static const command_rec dtcl_cmds[] =
{
    {"Dtcl_GlobalScript", set_globalscript, NULL, RSRC_CONF, TAKE1, "the name of the global configuration script"},
    {"Dtcl_ChildInitScript", set_initscript, NULL, RSRC_CONF, TAKE1, "the name of the per child init configuration script"},
    {"Dtcl_ChildExitScript", set_exitscript, NULL, RSRC_CONF, TAKE1, "the name of the per child exit configuration script"},
    {"Dtcl_CacheSize", set_cachesize, NULL, RSRC_CONF, TAKE1, "number of ttml scripts cached"},
    {NULL}
};

module MODULE_VAR_EXPORT dtcl_module =
{
    STANDARD_MODULE_STUFF,
    dtcl_init_handler,		/* initializer */
    NULL,			/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    create_dtcl_config,         /* server config */
    merge_dtcl_config,          /* merge server config */
    dtcl_cmds,                  /* command table */
    dtcl_handlers,		/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    dtcl_child_init,            /* child_init */
    dtcl_child_exit,            /* child_exit */
    NULL			/* post read-request */
};
