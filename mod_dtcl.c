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

/* mod_dtcl.c by David Welton <davidw@prosa.it> - originally mod_include.  */
/* Changes, improvements and bugfixes by Rolf Ade, Paolo Brutti and Patrick Diamond. */
/* Windows stuff by Jan Nijtmans. */

/*
 * http_include.c: Handles the server-parsed HTML documents
 *
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Apache module framework by rst.
 *
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
#define MULTIPART_FORM_DATA 1
/* #define DTCL_VERSION "X.X.X" */

/* *** Global variables *** */
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

static int upload_files_to_var = 0;     /* Upload files directly into
                                           Tcl variables, possibly
                                           using a lot of memory */

static char *upload_dir = "/tmp/";      /* Upload directory */
static unsigned int upload_max = 0;              /* Maximum amount of data that may be uploaded */

typedef struct {
    Tcl_Interp *server_interp;          /* per server Tcl interpreter */
    Tcl_Obj *dtcl_global_init_script;   /* run once when apache is first started */
    Tcl_Obj *dtcl_child_init_script;     
    Tcl_Obj *dtcl_child_exit_script;
    Tcl_Obj *dtcl_before_script;        /* script run before each page */
    Tcl_Obj *dtcl_after_script;         /*            after            */
    int dtcl_cache_size;
    char *server_name; 
} dtcl_server_conf;

#define GETREQINTERP(req) ((dtcl_server_conf *)ap_get_module_config(req->server->module_config, &dtcl_module))->server_interp

/* Functions for Tcl Channel */

static int closeproc(ClientData, Tcl_Interp *);
static int inputproc(ClientData, char *, int, int *);
static int outputproc(ClientData, char *, int, int *);
static int setoptionproc(ClientData, Tcl_Interp *, char *, char *);
/*
  static int getoptionproc(ClientData, Tcl_Interp *, char *, Tcl_DString *); */
static void watchproc(ClientData, int);
static int gethandleproc(ClientData, int, ClientData *);

/* Apache BUFF Channel Type */
static Tcl_ChannelType Achan = {
    "apache_channel",
    NULL,
    closeproc,
    inputproc,
    outputproc,
    NULL,
    setoptionproc,
    NULL,
    watchproc,
    gethandleproc,
    NULL
};

/* just need some arbitrary non-NULL pointer which can't also be a request_rec */
#define NESTED_INCLUDE_MAGIC	(&dtcl_module)

static char *dtcl_memcat(void *, int, void *, int);
static char *dtcl_memdup(void *, int);

static int memwrite(obuff *, char *, int);
static int multipart(char *, request_rec *, char *,  int);
static int parseargs(char *, request_rec *);
static int send_content(request_rec *);
static int send_parsed_file(request_rec *, char *, struct stat*, int);
static int send_tcl_file(request_rec *, char *, struct stat*);
static int set_header_type(request_rec *, char *);
static int print_headers(request_rec *);
static int print_error(request_rec *, int, char *);
static int flush_output_buffer(request_rec *);
static void tcl_init_stuff(server_rec *s, pool *p);

int inputproc(ClientData instancedata, char *buf, int toRead, int *errorCodePtr)
{
    return EINVAL;
}

/* This is the output 'method' for the Memory Buffer Tcl 'File'
   Channel that we create to divert stdout to */

static int outputproc(ClientData instancedata, char *buf, int toWrite, int *errorCodePtr)
{
    memwrite(&obuffer, buf, toWrite);
    return toWrite;		
} 

static int closeproc(ClientData instancedata, Tcl_Interp *interp2)
{
    flush_output_buffer(global_rr);
    return 0;
}

static int setoptionproc(ClientData instancedata, Tcl_Interp *interp, char *optionname, char *value)
{
    return TCL_OK;
}

/*
int getoptionproc(ClientData instancedata, Tcl_Interp *intepr,
				      char *optionname, Tcl_DString *dsPtr)
{
    return TCL_OK;
}
*/

static void watchproc(ClientData instancedata, int mask)
{
    /* not much to do here */
    return;
}

static int gethandleproc(ClientData instancedata, int direction, ClientData *handlePtr)
{
    return TCL_ERROR;
}

/* concatenate two memory regions  */

static char *dtcl_memcat(void *chunk1, int len1, void *chunk2, int len2)
{
    int sz = len1 + len2;
    chunk1 = realloc((char *)chunk1, sz * sizeof(char));    
    if (chunk1 == NULL)
    {
	fprintf(stderr, "ap_palloc barfed in memcat, len = %d!\n", sz);
	return NULL;
    }
    memset(chunk1 + len1, '\0', len2);
    memcpy(chunk1+len1, chunk2, len2);
    return chunk1;
}

/* "memdup" */

static char *dtcl_memdup(void *chunk, int len)
{
    char *buf = malloc(len * sizeof(char));
    if (buf == NULL)
    {
	fprintf(stderr, "ap_palloc barfed in memdup, len = %d!\n", len);
	return NULL;
    }
    memset(buf, '\0', len);
    memcpy(buf, chunk, len);
    return buf;
}

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
/* Macro to Tcl Objectify StringToUtf stuff */
#define STRING_TO_UTF_TO_OBJ(string) Tcl_NewStringObj(StringToUtf(string), -1)

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
	Tcl_WrongNumArgs(interp, 1, objv, "string");
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
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 
		     global_rr->server, "Mod_Dtcl Error: %s", 
		     Tcl_GetStringFromObj (objv[2], (int *)NULL));
    } else {
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	    return TCL_ERROR;
	}
	if (buffer_output == 1)
	{
	    memwrite(&obuffer, arg1, length);
	} else {
	    flush_output_buffer(global_rr);
	    ap_rwrite(arg1, length, global_rr);
	}
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
	Tcl_AddObjErrorInfo(interp, "Cannot manipulate headers - already sent", -1);
	return TCL_ERROR;
    }
    opt = Tcl_GetStringFromObj(objv[1], NULL);

    if (!strcmp("setcookie", opt)) /* ### setcookie ### */
    {
	char *val;
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
			     "headers setcookie cookie-name cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure?");
	    return TCL_ERROR;
	}

	/* SetCookie: foo=bar; EXPIRES=DD-Mon-YY HH:MM:SS; DOMAIN=domain; PATH=path; SECURE */

	val = Tcl_GetString(objv[3]);
	if (objv[2]->length == 0) 
	{
	    Tcl_AddObjErrorInfo(interp, "Need a name for cookie", -1);
	    return TCL_ERROR;
	}
	cookie = ap_pstrcat(global_rr->pool, cgiEncodeObj(objv[2]), "=", cgiEncodeObj(objv[3]), NULL);

	for (i = 4; i < objc; i++)
	{
	    if (Tcl_GetIndexFromObj(interp, objv[i], cookieParms, "option", 0, &idx) != TCL_OK)
	    {
		return TCL_ERROR;
	    } else if (idx == 4) {
		cookie = ap_pstrcat(global_rr->pool, cookie, cookieStrings[idx], NULL);
	    } else if (++i >= objc) {
		Tcl_WrongNumArgs(interp, 1, objv,
				 "headers setcookie cookie-name cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure?");
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
    } else if (!strcmp("numeric", opt)) /* ### numeric ### */
    {
	int st = 200;

	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "numeric response code");
	    return TCL_ERROR;
	}
	if (Tcl_GetIntFromObj(interp, objv[2], &st) != TCL_ERROR)
	    global_rr->status = st;
	else
	    return TCL_ERROR;
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
    char *authorization = NULL;

    time_t date = global_rr->request_time;

    int i;

    array_header *hdrs_arr;
    table_entry *hdrs;
    array_header *env_arr;
    table_entry  *env;

    Tcl_Obj *EnvsObj = Tcl_NewStringObj("::request::ENVS", -1);

    /* ensure that the system area which holds the cgi variables is empty */
    ap_clear_table(global_rr->subprocess_env);

    /* retrieve cgi variables */
    ap_add_cgi_vars(global_rr);
    ap_add_common_vars(global_rr);
    
    hdrs_arr = ap_table_elts(global_rr->headers_in);
    hdrs = (table_entry *) hdrs_arr->elts;
    
    env_arr =  ap_table_elts(global_rr->subprocess_env);
    env     = (table_entry *) env_arr->elts;

    /* Get the user/pass info for Basic authentication */
    (const char*)authorization = ap_table_get(global_rr->headers_in, "Authorization");
    if (authorization && !strcasecmp(ap_getword_nc(global_rr->pool, &authorization, ' '), "Basic"))
    {
	char *tmp;
	char *user;
	char *pass;

	tmp = ap_pbase64decode(global_rr->pool, authorization);
	user = ap_getword_nulls_nc(global_rr->pool, &tmp, ':');
	pass = tmp;
 	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::request::USER", -1), 
		       Tcl_NewStringObj("user", -1),
		       STRING_TO_UTF_TO_OBJ(user),
		       0);  
 	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::request::USER", -1), 
		       Tcl_NewStringObj("pass", -1),
		       STRING_TO_UTF_TO_OBJ(pass),
		       0);  
    } 

    /* These were the "include vars"  */
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DATE_LOCAL", -1), STRING_TO_UTF_TO_OBJ(ap_ht_time(global_rr->pool, date, timefmt, 0)), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DATE_GMT", -1), STRING_TO_UTF_TO_OBJ(ap_ht_time(global_rr->pool, date, timefmt, 1)), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("LAST_MODIFIED", -1), STRING_TO_UTF_TO_OBJ(ap_ht_time(global_rr->pool, global_rr->finfo.st_mtime, timefmt, 0)), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_URI", -1), STRING_TO_UTF_TO_OBJ(global_rr->uri), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_PATH_INFO", -1), STRING_TO_UTF_TO_OBJ(global_rr->path_info), 0);

#ifndef WIN32
    pw = getpwuid(global_rr->finfo.st_uid);
    if (pw)
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("USER_NAME", -1), STRING_TO_UTF_TO_OBJ(ap_pstrdup(global_rr->pool, pw->pw_name)), 0);
    else
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("USER_NAME", -1),
		    STRING_TO_UTF_TO_OBJ(ap_psprintf(global_rr->pool, "user#%lu", (unsigned long) global_rr->finfo.st_uid)), 0);
#endif

    if ((t = strrchr(global_rr->filename, '/')))
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_NAME", -1), STRING_TO_UTF_TO_OBJ(++t), 0);
    else
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_NAME", -1), STRING_TO_UTF_TO_OBJ(global_rr->uri), 0);

    if (global_rr->args)
    {
	char *arg_copy = ap_pstrdup(global_rr->pool, global_rr->args);
	ap_unescape_url(arg_copy);
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("QUERY_STRING_UNESCAPED", -1), STRING_TO_UTF_TO_OBJ(ap_escape_shell_cmd(global_rr->pool, arg_copy)), 0);
    }

    /* ----------------------------  */

    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
	if (!hdrs[i].key)
	    continue;
	/* turn cookies into variables  */
	if (!strncmp(hdrs[i].key, "Cookie", strlen("Cookie")))
	{
	    char *var, *var2;
	    char *val = NULL;
	    char *p = ap_pstrdup(global_rr->pool, hdrs[i].val);

	    var = p;

	    while(var)
	    {
		var2 = strchr(var, ';');
		if (var2 != NULL)
		{
		    *(var2++) = '\0';
		    if ((*var2 == ' ') && (*var2 != '\0'))
			var2++;
		}
		val = strchr(var, '=');
		
		if (val)
		{
		    char *discard = NULL; 
		    discard = strchr(val, ' ');
		    if (discard)
			*discard = '\0';
		    *val++ = '\0';
		    var = cgiDecodeString(var);
		    val = cgiDecodeString(val);
		} 
		Tcl_SetVar2(interp, "::request::COOKIES", cgiDecodeString(var), val, 0);
		var = var2;
	    }
	} else {
	    Tcl_ObjSetVar2(interp, EnvsObj, STRING_TO_UTF_TO_OBJ(hdrs[i].key), STRING_TO_UTF_TO_OBJ(hdrs[i].val), 0);
	}
    }

    /* transfer apache internal cgi variables to TCL request namespace */
    for (i = 0; i < env_arr->nelts; ++i)
    {
	if (!env[i].key)
	    continue;
	Tcl_ObjSetVar2(interp, EnvsObj, STRING_TO_UTF_TO_OBJ(env[i].key), STRING_TO_UTF_TO_OBJ(env[i].val), 0);
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

// if ((end + 2 != NULL) && !strncmp(end + 2, "--", 2))

    /* search buffer for \r\n, set end to location */
static char *crlfsearch(char *ptr, unsigned int len)
{
    unsigned int i;
    char *end = NULL;
    for (i = 0; i < len - 1; i ++) {
	if (ptr[i] == '\r') {
	    if (ptr[i+1] == '\n') {
		end = &ptr[i];
                break;
	    }
	}
    }
    return end;
}
/* For multipart/form-data */
#define CONTENT_DISP "Content-Disposition: form-data;"
#define CONTENT_DISP_LEN strlen(CONTENT_DISP)
#define CONTENT_TYPE "Content-type: "
#define CONTENT_TYPE_LEN strlen(CONTENT_TYPE)

#define DTCLUPLOAD "dtclXXXXXX"

static int multipart(char *inargs, request_rec *r, char *boundary, int length_read)
{
    static unsigned int buflen = 0;
    static int boundarysz = 0;
    static int state = 0;     /*  
				  0: normal
				  1: variable
				  2: file
			      */

    static char *buffer = NULL;

    static char *varname = NULL;

    static char *acum = NULL;
    static int acumlen = 0;

    static Tcl_Obj *val;
    static int tmpfilefd = 0;
    static char *tmpfilename = NULL;

    static unsigned int length_output = 0;

    char *baseptr = NULL;
    char *line = NULL;
    char *end = NULL;
    char *errstr = NULL;

    int retval = 0;
    int linelen = 0;
 
    Tcl_Interp *interp;
   
    interp = GETREQINTERP(r);
    /* init stuff */
    if (boundarysz == 0)
	boundarysz = strlen(boundary);

    if (tmpfilefd == 0 && !upload_files_to_var)
    {
	tmpfilename = ap_pstrcat(r->pool, upload_dir, DTCLUPLOAD, NULL);
	tmpfilefd = mkstemp(tmpfilename);
    }
    /* ---------- */

    if (buffer != NULL)
    {
	buffer = dtcl_memcat(buffer, buflen, inargs, length_read);
	baseptr = buffer;
	buflen = buflen + length_read;
    } else {
	buffer = dtcl_memdup(inargs, length_read);
	baseptr = buffer;
	buflen = length_read;
    }

    /* search base for \r\n, set end to location */
    end = crlfsearch(baseptr, buflen);

    while (end)
    {
	line = baseptr;
	linelen = end - baseptr;
 	baseptr = end + 2;
	buflen -= (linelen + 2);

	/* boundary is preceded by "--" */
	if (!strncmp (line, "--", 2) && !strncmp(line + 2, boundary, boundarysz)) 
	{
	    *end = '\0';
	    if (state == 1) { /* it's a variable  */
		/* don't do much...  */
	    } else if (state == 2) { /* it's a file  */	
		/* send to file, or stick in variable */
		if (upload_files_to_var != 0)
		{
		    Tcl_ObjSetVar2(interp, 
				   Tcl_NewStringObj("::request::UPLOAD", -1), 
				   Tcl_NewStringObj("data", -1), 
				   Tcl_NewByteArrayObj(acum, acumlen), 
				   0);
		    free(acum);
		    acum = NULL;
		    acumlen = 0;
		} else {
		    Tcl_ObjSetVar2(interp, 
				   Tcl_NewStringObj("::request::UPLOAD", -1), 
				   Tcl_NewStringObj("realname", -1), 
				   Tcl_NewStringObj(tmpfilename, -1),
				   0);

		    close(tmpfilefd);
		    /* close FD */
		}
	    }
	    varname = NULL;
	    val = NULL;
	    state = 0;
	    /* check to see if the boundary is followed by "--" */
	    if ((line + boundarysz + 2) != NULL &&
		*(line + boundarysz + 2) == '-' &&
		(line + boundarysz + 3) != NULL &&
		*(line + boundarysz + 3) == '-')
		goto cleanup;
	    
	} else if (!strncasecmp(line, CONTENT_DISP, CONTENT_DISP_LEN)) {
	    /* Parse stuff like this: name="foobar"; filename="blah.txt" */
	    char *vars; 
	    char *base;
	    int varlen;
	    int linestate = 0; /* 1 = inside quotes */
	    *end = '\0';
	    vars = line + CONTENT_DISP_LEN + 1;
	    base = vars;
	    varlen = strlen(vars);
		
	    while (varlen)
	    {
		if (*vars == '=') {
		    *vars = '\0';
		    if (!strcmp(base, "filename"))
			state = 2;
		    else if (!strcmp(base, "name"))
			state = 1;
		    else
		    {
			errstr = "Problems with multipart form data (file upload), state = %d";
			goto multi_error;
		    }
		    vars ++;
		    base = vars;
		} else if (*vars == '"') {
		    if (linestate == 1)
		    {
			*vars = '\0';
			if (state == 1) /* it's a variable name */
			    varname = ap_pstrdup(r->pool, base);
			else /* it's a filename */
			{
			    Tcl_ObjSetVar2(interp, 
					   Tcl_NewStringObj("::request::UPLOAD", -1), 
					   Tcl_NewStringObj("filename", -1), 
					   Tcl_NewStringObj(base, -1), 
					   0);
			}
			
			linestate = 0;
		    } else {
			linestate = 1;
		    }
		    vars ++;
		    base = vars;
		} else if (*vars == ';') {
		    vars ++;
		    base = vars;
		} else if (*vars == ' ') {
		    if (linestate == 0) 
			base ++;
		    vars ++;
		} else {
		    vars ++;
		}
		varlen --;
	    }
	} else if (!strncasecmp(line, CONTENT_TYPE, CONTENT_TYPE_LEN)) {
	    /* do something with content type */
	    *end = '\0';
	    line += CONTENT_TYPE_LEN;
	    Tcl_ObjSetVar2(interp, 
			   Tcl_NewStringObj("::request::UPLOAD", -1),
			   Tcl_NewStringObj("type", -1),
			   Tcl_NewStringObj(line, strlen(line)), /* kill end of line */
			   0);
	} else { /* ordinary line */

	    if (state == 0) {
		/* don't do much */
	    } else if (state == 1) { /* it's a variable */
		if (linelen > 0) /* make sure it's not blank */
		{
		    *end = '\0';
		    Tcl_ObjSetVar2(interp,
				   Tcl_NewStringObj("::request::VARS", -1),
				   Tcl_NewStringObj(varname, -1),
				   Tcl_NewStringObj(line, -1), 0);
		}
	    } else if (state == 2) {
		int sz = end - line;
		if (sz > 0)
		{
		    if (end + 4 + boundarysz != NULL) /* make sure not to overrun */
			if (strncmp (end+2, "--", 2) && strncmp(end + 4, boundary, boundarysz))
			{
//			    buflen -= 2;
			    sz += 2; /* reset stuff if we get \r\n in the middle of a file upload */
			}
		    if (upload_files_to_var != 0)
		    {
			if (acumlen == 0)
			    acum = dtcl_memdup(line, sz);
			else 
			    acum = dtcl_memcat(acum, acumlen, line, sz);
			
			acumlen += sz;
		    } else {
			write(tmpfilefd, line, sz);
		    }
		    length_output += sz;
		    if (length_output > upload_max && upload_max != 0)
		    {
			errstr = "File upload size exceeded limit";
			goto multi_error;
		    }
		}
	    } 
	}
	baseptr = dtcl_memdup(baseptr, buflen);
	free(buffer);
	buffer = baseptr;
	end = crlfsearch(baseptr, buflen);
    }

    if (buflen && state == 2)
    {
	if (!upload_files_to_var)
	{
	    write(tmpfilefd, baseptr, buflen);
	} else {
	    if (acumlen == 0)
		acum = dtcl_memdup(baseptr, buflen);
	    else 
		acum = dtcl_memcat(acum, acumlen, baseptr, buflen);
	    
	    acumlen += buflen;
	}
	length_output += buflen;
	if (length_output > upload_max && upload_max != 0)
	{
	    errstr = "File upload size exceeded limit";
	    goto multi_error;
	}       
	buflen = 0;
	free(buffer);
	buffer = NULL;
	baseptr = NULL;
    }
    
    return 0;

    /* Because it's convenient. */   
multi_error:
    retval = -1;
    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
		 errstr, state);
    
cleanup:
    /* return things to normal */
    buflen = 0;
    boundarysz = 0;
    if (buffer != NULL)
    {
	free(buffer);
	buffer = NULL;
	baseptr = NULL;
    }
    if (acum != NULL)
    {
	free(acum);
	acum = NULL;
    }
    acumlen = 0;
    varname = NULL;
    val = NULL;
    state = 0;
    if (!upload_files_to_var && tmpfilefd)
	close(tmpfilefd);
    tmpfilefd = 0;
    tmpfilename = ap_pstrcat(r->pool, upload_dir, DTCLUPLOAD, NULL);

    length_output = 0;

    return retval;
}

/* This function does the GET/POST variables passed to us  */
static int parseargs(char *inargs, request_rec *r)
{
    char *line, *cp, *var = NULL, *val = NULL, *linept;

    int i, numargs;

    Tcl_Interp *interp = GETREQINTERP(r);

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
	    Tcl_Obj *newval = STRING_TO_UTF_TO_OBJ(cgiDecodeString(val));
	    Tcl_Obj *newvar = STRING_TO_UTF_TO_OBJ(cgiDecodeString(var));
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

    Tcl_Interp *interp = GETREQINTERP(r);

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

    Tcl_Interp *interp = GETREQINTERP(r);

    /* Look for the script's compiled version. If it's not found, create it. */
    hashKey = ap_psprintf(r->pool, "%s%ld%ld%d", filename, finfo->st_mtime, finfo->st_ctime, toplevel);
    entry = Tcl_CreateHashEntry(&objCache, hashKey, &isNew);
    if (isNew || !cacheSize) {
	/* BEGIN PARSER  */
	char inside = 0;	/* are we inside the starting/ending delimiters  */
	
	dtcl_server_conf *dsc = NULL;
	const char *strstart = STARTING_SEQUENCE;
	const char *strend = ENDING_SEQUENCE;

	char c;
	int ch;
	int l = strlen(ENDING_SEQUENCE), l2 = strlen(STARTING_SEQUENCE), p = 0;

	FILE *f = NULL;

	dsc = (dtcl_server_conf *) ap_get_module_config(r->server->module_config, &dtcl_module);
	if (!(f = ap_pfopen(r->pool, filename, "r")))
	{
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "file permissions deny server access: %s", filename);
	    return HTTP_FORBIDDEN;
	}

	/* Beginning of the file parser */
	if (toplevel)
	{
	    outbuf = Tcl_NewStringObj("namespace eval request {\n", -1);
	    if (dsc->dtcl_before_script)
		Tcl_AppendObjToObj(outbuf, dsc->dtcl_before_script);
	    Tcl_AppendToObj(outbuf, "buffer_add \"", -1);
	}
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
	    Tcl_AppendToObj(outbuf, "\"\n", 2);
	}
	
	if (toplevel)
	{
	    if (dsc->dtcl_after_script)
		Tcl_AppendObjToObj(outbuf, dsc->dtcl_after_script);
	    
	    Tcl_AppendToObj(outbuf, "\n}\nnamespace delete request\n", -1);
	}
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
    int content_type = 0;

    char *string_content_type;
    char *boundary = NULL;
    
    Tcl_Interp *interp;

    global_rr = r;		/* Assign request to global request var */

    interp = GETREQINTERP(r);

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

    /* Check and see if it's multipart/form-data, and grab the boundary if so */
    (const char*)string_content_type = ap_table_get(r->headers_in, "Content-type");
    if (string_content_type != NULL)
	if (!strncasecmp(string_content_type, "multipart/form-data", 19))
	{	
	    content_type = MULTIPART_FORM_DATA;
	    boundary = strchr(string_content_type, '=') + 1;
	}

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

	    if (content_type != MULTIPART_FORM_DATA) 
	    {
		if (argscumulative != NULL)
		    argscumulative = ap_pstrcat(r->pool, argscumulative, argsbuffer, NULL);
		else
		    argscumulative = ap_pstrdup(r->pool, argsbuffer);
	    } else {
		multipart(argsbuffer, r, boundary, len_read);
	    }
	}

 	if (content_type != MULTIPART_FORM_DATA)
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

static void tcl_init_stuff(server_rec *s, pool *p)
{
    int rslt;
    Tcl_Channel achan;
    Tcl_Interp *interp;
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(s->module_config, &dtcl_module);
    server_rec *sr;

    /* Initialize TCL stuff  */

    interp = Tcl_CreateInterp();
    dsc->server_interp = interp; /* root interpreter */    

    /* Create TCL commands to deal with Apache's BUFFs. */
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
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Config string = \"%s\"", Tcl_GetStringFromObj(dsc->dtcl_global_init_script, NULL));  /* XXX */
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Cache size = \"%d\"", dsc->dtcl_cache_size);  /* XXX */
#endif

    if (dsc->dtcl_global_init_script != NULL)
    {
	rslt = Tcl_EvalObjEx(interp, dsc->dtcl_global_init_script, 0);
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
	    cacheSize = 10; /* Arbitrary number FIXME */
	cacheFreeSize = cacheSize;
    }
    /* Initializing cache structures */
    objCacheList = malloc(cacheSize * sizeof(char *));
    Tcl_InitHashTable(&objCache, TCL_STRING_KEYS);

    sr = s;
    while (sr)
    {
	/* Ok, this stuff should set up slave interpreters for other
           virtual hosts */
	dtcl_server_conf *mydsc = (dtcl_server_conf *) ap_get_module_config(sr->module_config, &dtcl_module);
	if (!mydsc->server_interp)
	{
	    mydsc->server_interp = Tcl_CreateSlave(interp, sr->server_hostname, 0);
	    Tcl_CreateAlias(mydsc->server_interp, "buffer_add", interp, "buffer_add", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "hputs", interp, "hputs", 0, NULL);	    
	    Tcl_CreateAlias(mydsc->server_interp, "buffered", interp, "buffered", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "headers", interp, "headers", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "hgetvars", interp, "hgetvars", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "include", interp, "include", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "parse", interp, "parse", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "hflush", interp, "hflush", 0, NULL);
	    Tcl_CreateAlias(mydsc->server_interp, "dtcl_info", interp, "dtcl_info", 0, NULL);
	    Tcl_SetChannelOption(mydsc->server_interp, achan, "-buffering", "none");
	    Tcl_RegisterChannel(mydsc->server_interp, achan);
	}
	mydsc->server_name = ap_pstrdup(p, sr->server_hostname);
	sr = sr->next;
    }
}

void dtcl_init_handler(server_rec *s, pool *p)
{
#if THREADED_TCL == 0
    tcl_init_stuff(s, p);
#endif
    ap_add_version_component("mod_dtcl");
}

static const char *set_script(cmd_parms *cmd, void *dummy, char *arg, char *arg2)
{
    Tcl_Obj *objarg;
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);

    if (arg == NULL || arg2 == NULL)
	return "Mod_Dtcl Error: Dtcl_Script requires two arguments";
   
    objarg = Tcl_NewStringObj(arg2, -1);
    Tcl_AppendToObj(objarg, "\n", 1);
    if (strcmp(arg, "GlobalInitScript") == 0) {
	dsc->dtcl_global_init_script = objarg;
    } else if (strcmp(arg, "ChildInitScript") == 0) {
	dsc->dtcl_child_init_script = objarg;
    } else if (strcmp(arg, "ChildExitScript") == 0) {
	dsc->dtcl_child_exit_script = objarg;
    } else if (strcmp(arg, "BeforeScript") == 0) {
	dsc->dtcl_before_script = objarg;
    } else if (strcmp(arg, "AfterScript") == 0) {
	dsc->dtcl_after_script = objarg;
    } else {
	return "Mod_Dtcl Error: Dtcl_Script must have a second argument, which is one of: GlobalInitScript, ChildInitScript, ChildExitScript, BeforeScript, AfterScript";
    }
    return NULL;
}

static const char *set_cachesize(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    dsc->dtcl_cache_size = strtol(arg, NULL, 10);
    return NULL;
}

static const char *set_uploaddir(cmd_parms *cmd, void *dummy, char *arg)
{
    upload_dir = arg;
    return NULL;
}
static const char *set_uploadmax(cmd_parms *cmd, void *dummy, char *arg)
{
    upload_max = strtol(arg, NULL, 10);
    return NULL;
}
static const char *set_filestovar(cmd_parms *cmd, void *dummy, char *arg)
{
    upload_files_to_var = strtol(arg, NULL, 10);
    return NULL;
}

static void *create_dtcl_config(pool *p, server_rec *s)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));

    dsc->dtcl_global_init_script = NULL;
    dsc->dtcl_child_init_script = NULL;
    dsc->dtcl_child_exit_script = NULL;
    dsc->dtcl_before_script = NULL;
    dsc->dtcl_after_script = NULL;
    dsc->dtcl_cache_size = 0;
    dsc->server_name = ap_pstrdup(p, s->server_hostname);
    return dsc;
}

static void *merge_dtcl_config(pool *p, void *basev, void *overridesv)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));
    dtcl_server_conf *base = (dtcl_server_conf *) basev;
    dtcl_server_conf *overrides = (dtcl_server_conf *) overridesv;

    dsc->server_interp = overrides->server_interp ? overrides->server_interp : base->server_interp;
    dsc->dtcl_global_init_script = overrides->dtcl_global_init_script ? overrides->dtcl_global_init_script :	base->dtcl_global_init_script;
    dsc->dtcl_child_init_script = overrides->dtcl_child_init_script ? overrides->dtcl_child_init_script : base->dtcl_child_init_script;     
    dsc->dtcl_child_exit_script = overrides->dtcl_child_exit_script ? overrides->dtcl_child_exit_script : base->dtcl_child_exit_script;
    dsc->dtcl_before_script = overrides->dtcl_before_script ? overrides->dtcl_before_script : base->dtcl_before_script;
    dsc->dtcl_after_script = overrides->dtcl_after_script ? overrides->dtcl_after_script : base->dtcl_after_script;
    dsc->dtcl_cache_size = overrides->dtcl_cache_size ? overrides->dtcl_cache_size : base->dtcl_cache_size;
    dsc->server_name = overrides->server_name ? overrides->server_name : base->server_name; 
    return dsc;
}

static void dtcl_child_init(server_rec *s, pool *p)
{
    server_rec *sr;
    dtcl_server_conf *dsc;

#if THREADED_TCL == 1
    tcl_init_stuff(s, p);
#endif

    sr = s;
    while(sr)
    {	
	dsc = (dtcl_server_conf *) ap_get_module_config(sr->module_config, &dtcl_module);
	if (dsc->dtcl_child_init_script != NULL)
	    if (Tcl_EvalObjEx(dsc->server_interp, dsc->dtcl_child_init_script, 0) != TCL_OK)
		ap_log_error(APLOG_MARK, APLOG_ERR, s,
			     "Problem running child init script: %s", Tcl_GetString(dsc->dtcl_child_init_script));
	sr = sr->next;
    }
}

static void dtcl_child_exit(server_rec *s, pool *p)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(s->module_config, &dtcl_module);

    if (dsc->dtcl_child_exit_script != NULL)
	if (Tcl_EvalObjEx(dsc->server_interp, dsc->dtcl_child_exit_script, 0) != TCL_OK)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "Problem running child exit script: %s", Tcl_GetStringFromObj(dsc->dtcl_child_exit_script, NULL));
}

static const handler_rec dtcl_handlers[] =
{
    {"application/x-httpd-tcl", send_content},
    {"application/x-dtcl-tcl", send_content},
    {NULL}
};

static const command_rec dtcl_cmds[] =
{
    {"Dtcl_Script", set_script, NULL, RSRC_CONF, TAKE2, "Dtcl_Script GlobalInitScript|ChildInitScript|ChildExitScript|BeforeScript|AfterScript scriptname.tcl"},
    {"Dtcl_CacheSize", set_cachesize, NULL, RSRC_CONF, TAKE1, "Dtcl_Cachesize cachesize"},
    {"Dtcl_UploadDirectory", set_uploaddir, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadDirectory dirname"},
    {"Dtcl_UploadMaxSize", set_uploadmax, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadMaxSize size"},
    {"Dtcl_UploadFilesToVar", set_filestovar, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadFilesToVar 1/0"},
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

/*
Local Variables: ***
compile-command: "./builddtcl.sh shared" ***
End: ***
*/
