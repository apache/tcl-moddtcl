/* Copyright David Welton 1998, 1999 */

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000, 2001 The Apache Software Foundation.  All rights
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
 * 5. Products derived from this software may not be called "mod_dtcl"
 *    or "dtcl", nor may "dtcl" appear in their name, without prior
 *    written permission of the Apache Software Foundation.
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
 * University of Illinois, Urbana-Champaign.  */

/* $Id$  */

/* mod_dtcl.c by David Welton <davidw@apache.org> - originally mod_include.  */
/* See http://tcl.apache.org/mod_dtcl/credits.ttml for additional credits. */

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

#include "tcl_commands.h"
#include "parser.h"
#include "apache_request.h"
#include "mod_dtcl.h"

/* *** Global variables *** */
Tcl_Encoding system_encoding;    /* Default encoding  */

module MODULE_VAR_EXPORT dtcl_module;

static void tcl_init_stuff(server_rec *s, pool *p);
static void copy_dtcl_config(pool *p, dtcl_server_conf *olddsc, dtcl_server_conf *newdsc);
static int get_ttml_file(request_rec *r, dtcl_server_conf *dsc, Tcl_Interp *interp, char *filename, int toplevel, Tcl_Obj *outbuf);
static int send_content(request_rec *);
static int execute_and_check(Tcl_Interp *interp, Tcl_Obj *outbuf, request_rec *r);

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

static int inputproc(ClientData instancedata, char *buf, int toRead, int *errorCodePtr)
{
    return EINVAL;
}

/* This is the output 'method' for the Memory Buffer Tcl 'File'
   Channel that we create to divert stdout to */

static int outputproc(ClientData instancedata, char *buf, int toWrite, int *errorCodePtr)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *)instancedata;
    memwrite(dsc->obuffer, buf, toWrite);
    return toWrite;
}

static int closeproc(ClientData instancedata, Tcl_Interp *interp)
{
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    print_headers(globals->r);
    flush_output_buffer(globals->r);
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

/* Write something to the output buffer structure */

int memwrite(obuff *buffer, char *input, int len)
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

int set_header_type(request_rec *r, char *header)
{
    dtcl_server_conf *dsc = dtcl_get_conf(r);
    if (*(dsc->headers_set) == 0)
    {
	r->content_type = header;
	*(dsc->headers_set) = 1;
	return 1;
    } else {
	return 0;
    }
}

/* Printer headers if they haven't been printed yet */

int print_headers(request_rec *r)
{
    dtcl_server_conf *dsc = dtcl_get_conf(r);
    if (*(dsc->headers_printed) == 0)
    {
	if (*(dsc->headers_set) == 0)
	    set_header_type(r, DEFAULT_HEADER_TYPE);

	ap_send_http_header(r);
	*(dsc->headers_printed) = 1;
	return 1;
    } else {
	return 0;
    }
}

/* Print nice HTML formatted errors */

int print_error(request_rec *r, int htmlflag, char *errstr)
{
    set_header_type(r, DEFAULT_HEADER_TYPE);
    print_headers(r);

    if (htmlflag != 1)
	ap_rputs(ER1, r);

    if (errstr != NULL)
    {
	if (htmlflag != 1)
	{
	    ap_rputs(ap_escape_html(r->pool, errstr), r);
	} else {
	    ap_rputs(errstr, r);
	}
    }
    if (htmlflag != 1)
	ap_rputs(ER2, r);

    return 0;
}

/* Make sure that everything in the output buffer has been flushed. */

int flush_output_buffer(request_rec *r)
{
    dtcl_server_conf *dsc = dtcl_get_conf(r);
    if (dsc->obuffer->len != 0)
    {
	ap_rwrite(dsc->obuffer->buf, dsc->obuffer->len, r);
	Tcl_Free(dsc->obuffer->buf);
	dsc->obuffer->len = 0;
	dsc->obuffer->buf = NULL;
    }
    *(dsc->content_sent) = 1;
    return 0;
}

/* Function to convert strings to UTF encoding */

char *StringToUtf(char *input, ap_pool *pool)
{
#if DTCL_I18N == 1
    char *temp;
    Tcl_DString dstr;
    Tcl_DStringInit(&dstr);
    Tcl_ExternalToUtfDString(system_encoding, input, strlen(input), &dstr);

    temp = ap_pstrdup(pool, Tcl_DStringValue(&dstr));
    Tcl_DStringFree(&dstr);
    return temp;
#else
    /* If we aren't using the i18n stuff, no need to do anything */
    return input;
#endif
}

/* Function to be used should we desire to upload files to a variable */

#if 0
int dtcl_upload_hook(void *ptr, char *buf, int len, ApacheUpload *upload)
{
    Tcl_Interp *interp = ptr;
    static int usenum = 0;
    static int uploaded = 0;

    if (oldptr != upload)
    {
    } else {
    }

#if USE_ONLY_UPLOAD_COMMAND == 0

    Tcl_ObjSetVar2(interp,
		   Tcl_NewStringObj("::request::UPLOAD", -1),
		   Tcl_NewStringObj("data", -1),
		   Tcl_DuplicateObj(uploadstorage[usenum]),
		   0);
#endif /* USE_ONLY_UPLOAD_COMMAND  */
    return len;
}
#endif /* 0 */


/* Load, cache and eval a Tcl file  */

static int get_tcl_file(request_rec *r, Tcl_Interp *interp, char *filename, Tcl_Obj *outbuf)
{
    int result = 0;
#if 1
    /* Taken, in part, from tclIOUtil.c out of the Tcl
       distribution, and modified */

    /* Basically, what we are doing here is a Tcl_EvalFile, but
       with the addition of caching code. */
    char *cmdBuffer = (char *) NULL;
    Tcl_Channel chan = Tcl_OpenFileChannel(interp, r->filename, "r", 0644);
    if (chan == (Tcl_Channel) NULL)
    {
	Tcl_ResetResult(interp);
	Tcl_AppendResult(interp, "couldn't read file \"", r->filename,
			 "\": ", Tcl_PosixError(interp), (char *) NULL);
	goto error;
    }

    result = Tcl_ReadChars(chan, outbuf, r->finfo.st_size, 1);
    if (result < 0)
    {
	Tcl_Close(interp, chan);
	Tcl_AppendResult(interp, "couldn't read file \"", r->filename,
			 "\": ", Tcl_PosixError(interp), (char *) NULL);
	goto error;
    }

    if (Tcl_Close(interp, chan) != TCL_OK)
	goto error;

    /* yuck  */
    goto end;
error:
    if (cmdBuffer != (char *) NULL) {
	free(cmdBuffer);
    }
    return TCL_ERROR;

end:
    return TCL_OK;
#else
    Tcl_EvalFile(interp, r->filename);
#endif /* 1 */
}

/* Parse and execute a ttml file */

static int get_ttml_file(request_rec *r, dtcl_server_conf *dsc, Tcl_Interp *interp, char *filename, int toplevel, Tcl_Obj *outbuf)
{
    /* BEGIN PARSER  */
    int inside = 0;	/* are we inside the starting/ending delimiters  */


    FILE *f = NULL;

    if (!(f = ap_pfopen(r->pool, filename, "r")))
    {
	ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
		     "file permissions deny server access: %s", filename);
	return HTTP_FORBIDDEN;
    }

    if (toplevel)
    {
	Tcl_SetStringObj(outbuf, "namespace eval request {\n", -1);
	if (dsc->dtcl_before_script) {
	    Tcl_AppendObjToObj(outbuf, dsc->dtcl_before_script);
	} 
	Tcl_AppendToObj(outbuf, "buffer_add \"", -1);
    }
    else
	Tcl_SetStringObj(outbuf, "hputs \"\n", -1);

    /* if inside < 0, it's an error  */
    inside = dtcl_parser(outbuf, f);
    if (inside < 0)
    {
	if (ferror(f))
	{
	    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
			 "Encountered error in mod_dtcl getchar routine while reading %s",
			 r->uri);
	    ap_pfclose( r->pool, f);
	}
    }

    ap_pfclose(r->pool, f);

    if (inside == 0)
    {
	Tcl_AppendToObj(outbuf, "\"\n", 2);
    }

    if (toplevel)
    {
	if (dsc->dtcl_after_script)
	    Tcl_AppendObjToObj(outbuf, dsc->dtcl_after_script);

/* 	Tcl_AppendToObj(outbuf, "\n}\nnamespace delete request\n", -1); seems redundant */
	Tcl_AppendToObj(outbuf, "\n}\n", -1);
    }
    else
	Tcl_AppendToObj(outbuf, "\n", -1);

#if DTCL_I18N == 1
    /* Convert to encoding  */
    Tcl_SetStringObj(outbuf, StringToUtf(Tcl_GetString(outbuf), r->pool), -1);
#endif

    /* END PARSER  */
    return TCL_OK;
}

/* Calls Tcl_EvalObj() and checks for errors; prints the error buffer if any. */

static int execute_and_check(Tcl_Interp *interp, Tcl_Obj *outbuf, request_rec *r)
{
    char *errorinfo;
    dtcl_server_conf *conf = NULL;

    conf = dtcl_get_conf(r);
    if (Tcl_EvalObj(interp, outbuf) == TCL_ERROR)
    {
	Tcl_Obj *errscript = conf->dtcl_error_script ? conf->dtcl_error_script :
	    conf->dtcl_error_script ? conf->dtcl_error_script : NULL;

        print_headers(r);
        flush_output_buffer(r);
        if (errscript)
        {
	    if (Tcl_EvalObj(interp, errscript) == TCL_ERROR)
                print_error(r, 1, "<b>Tcl_ErrorScript failed!</b>");
        } else {
            /* default action  */
            errorinfo = Tcl_GetVar(interp, "errorInfo", 0);
            print_error(r, 0, errorinfo);
            print_error(r, 1, "<p><b>OUTPUT BUFFER:</b></p>");
            print_error(r, 0, Tcl_GetStringFromObj(outbuf, (int *)NULL));
        }
/*                  "</pre><b>OUTPUT BUFFER</b><pre>\n",
                    Tcl_GetStringFromObj(outbuf, (int *)NULL));  */
    } else {
        /* We make sure to flush the output if buffer_add was the only output */
        print_headers(r);
        flush_output_buffer(r);
    }
    return OK;
}

/* This is a seperate function so that it may be called from 'Parse' */

int get_parse_exec_file(request_rec *r, dtcl_server_conf *dsc, int toplevel)
{
    char *hashKey = NULL;
    int isNew = 0;
    int result = 0;

    Tcl_Obj *outbuf = NULL;
    Tcl_HashEntry *entry = NULL;
    Tcl_Interp *interp = dsc->server_interp;

    /* Look for the script's compiled version. If it's not found,
       create it. */
    if (*(dsc->cache_size))
    {
	hashKey = ap_psprintf(r->pool, "%s%ld%ld%d", r->filename, r->finfo.st_mtime, r->finfo.st_ctime, toplevel);
	entry = Tcl_CreateHashEntry(dsc->objCache, hashKey, &isNew);
    }
    if (isNew || *(dsc->cache_size) == 0)
    {
	outbuf = Tcl_NewObj();
	Tcl_IncrRefCount(outbuf);

	if(!strcmp(r->content_type, "application/x-httpd-tcl"))
	{
	    /* It's a TTML file  */
	    result = get_ttml_file(r, dsc, interp, r->filename, 1, outbuf);
	} else {
	    /* It's a plain Tcl file */
	    result = get_tcl_file(r, interp, r->filename, outbuf);
	}
	if (result != TCL_OK)
	    return result;

	if (*(dsc->cache_size))
	    Tcl_SetHashValue(entry, (ClientData)outbuf);

	if (*(dsc->cache_free)) {
	    dsc->objCacheList[-- *(dsc->cache_free) ] = strdup(hashKey);
	} else if (*(dsc->cache_size)) { /* if it's zero, we just skip this... */
	    Tcl_HashEntry *delEntry;
	    delEntry = Tcl_FindHashEntry(dsc->objCache, dsc->objCacheList[*(dsc->cache_size) - 1]);
	    Tcl_DecrRefCount((Tcl_Obj *)Tcl_GetHashValue(delEntry));
	    Tcl_DeleteHashEntry(delEntry);
	    free(dsc->objCacheList[*(dsc->cache_size) - 1]);
	    memmove((dsc->objCacheList) + 1, dsc->objCacheList, sizeof(char *) * (*(dsc->cache_size) -1));
	    dsc->objCacheList[0] = strdup(hashKey);
	}
    } else {
	outbuf = (Tcl_Obj *)Tcl_GetHashValue(entry);
    }
    execute_and_check(interp, outbuf, r);
    return TCL_OK;
}

/* Set things up to execute a file, then execute */

static int send_content(request_rec *r)
{
    char error[MAX_STRING_LEN];
    char timefmt[MAX_STRING_LEN];

    int errstatus;

    Tcl_Interp *interp;
    
    dtcl_interp_globals *globals = NULL;
    dtcl_server_conf *dsc = NULL;
    dsc = dtcl_get_conf(r);
    globals = ap_pcalloc(r->pool, sizeof(dtcl_interp_globals));
    globals->r = r;
    interp = dsc->server_interp;
    Tcl_SetAssocData(interp, "dtcl", NULL, globals);

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

    ap_cpystrn(error, DEFAULT_ERROR_MSG, sizeof(error));
    ap_cpystrn(timefmt, DEFAULT_TIME_FORMAT, sizeof(timefmt));
    ap_chdir_file(r->filename);

    if (Tcl_EvalObj(interp, dsc->namespacePrologue) == TCL_ERROR)
    {
	ap_log_error(APLOG_MARK, APLOG_ERR, r->server, "Could not create request namespace\n");
	return HTTP_BAD_REQUEST;
    }

    /* Apache Request stuff */

    globals->req = ApacheRequest_new(r);

    ApacheRequest_set_post_max(globals->req, dsc->upload_max);
    ApacheRequest_set_temp_dir(globals->req, dsc->upload_dir);

#if 0
    if (upload_files_to_var)
    {
	globals->req->hook_data = interp;
	globals->req->upload_hook = dtcl_upload_hook;
    }
#endif

    ApacheRequest___parse(globals->req);

    /* take results and create tcl variables from them */
#if USE_ONLY_VAR_COMMAND == 0
    if (globals->req->parms)
    {
	int i;
	array_header *parmsarray = ap_table_elts(globals->req->parms);
	table_entry *parms = (table_entry *)parmsarray->elts;
	Tcl_Obj *varsobj = Tcl_NewStringObj("::request::VARS", -1);
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    if (!parms[i].key)
		continue;
	    else {
		/* All this is so that a query like x=1&x=2&x=3 will
                   produce a variable that is a list */
		Tcl_Obj *newkey = STRING_TO_UTF_TO_OBJ(parms[i].key, r->pool);
		Tcl_Obj *newval = STRING_TO_UTF_TO_OBJ(parms[i].val, r->pool);
		Tcl_Obj *oldval = Tcl_ObjGetVar2(interp, varsobj, newkey, 0);

		if (oldval == NULL)
		{
		    Tcl_ObjSetVar2(interp, varsobj, newkey, newval, 0);
		} else {
		    Tcl_Obj *concat[2];
		    concat[0] = oldval;
		    concat[1] = newval;
		    Tcl_ObjSetVar2(interp, varsobj, newkey, Tcl_ConcatObj(2, concat), 0);
		}
	    }
	}

    }
#endif
#if USE_ONLY_UPLOAD_COMMAND == 1
    upload = req->upload;
    /* Loop through uploaded files */
    while (upload)
    {
	char *type = NULL;
	char *channelname = NULL;
	Tcl_Channel chan;

	/* The name of the file uploaded  */
	Tcl_ObjSetVar2(interp,
		       Tcl_NewStringObj("::request::UPLOAD", -1),
		       Tcl_NewStringObj("filename", -1),
		       Tcl_NewStringObj(upload->filename, -1),
		       TCL_LIST_ELEMENT|TCL_APPEND_VALUE);

	/* The variable name of the file upload */
	Tcl_ObjSetVar2(interp,
		       Tcl_NewStringObj("::request::UPLOAD", -1),
		       Tcl_NewStringObj("name", -1),
		       Tcl_NewStringObj(upload->name, -1),
		       TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
	Tcl_ObjSetVar2(interp,
		       Tcl_NewStringObj("::request::UPLOAD", -1),
		       Tcl_NewStringObj("size", -1),
		       Tcl_NewIntObj(upload->size),
		       TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
	type = (char *)ap_table_get(upload->info, "Content-type");
	if (type)
	{
	    Tcl_ObjSetVar2(interp,
			   Tcl_NewStringObj("::request::UPLOAD", -1),
			   Tcl_NewStringObj("type", -1),
			   Tcl_NewStringObj(type, -1), /* kill end of line */
			   TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
	}
	if (!upload_files_to_var)
	{
	    if (upload->fp != NULL)
	    {
		chan = Tcl_MakeFileChannel((ClientData)fileno(upload->fp), TCL_READABLE);
		Tcl_RegisterChannel(interp, chan);
		channelname = Tcl_GetChannelName(chan);
		Tcl_ObjSetVar2(interp,
			       Tcl_NewStringObj("::request::UPLOAD", -1),
			       Tcl_NewStringObj("channelname", -1),
			       Tcl_NewStringObj(channelname, -1), /* kill end of line */
			       TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
	    }
	}

	upload = upload->next;
    }
#endif /* USE_ONLY_UPLOAD_COMMAND == 1 */

    get_parse_exec_file(r, dsc, 1);
    /* reset globals  */
    *(dsc->buffer_output) = 0;
    *(dsc->headers_printed) = 0;
    *(dsc->headers_set) = 0;
    *(dsc->content_sent) = 0;

    return OK;
}

/* This is done in two places, so I decided to group the creates in
   one function */

static void tcl_create_commands(dtcl_server_conf *dsc)
{
    Tcl_Interp *interp = dsc->server_interp;
    Tcl_CreateObjCommand(interp, "hputs", Hputs, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "buffer_add", Buffer_Add, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "buffered", Buffered, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "headers", Headers, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "hgetvars", HGetVars, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "var", Var, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "upload", Upload, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "include", Include, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "parse", Parse, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "hflush", HFlush, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "dtcl_info", Dtcl_Info, NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "no_body", No_Body, NULL, (Tcl_CmdDeleteProc *)NULL);
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
    achan = Tcl_CreateChannel(&Achan, "apacheout", dsc, TCL_WRITABLE);

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
    tcl_create_commands(dsc);
    dsc->namespacePrologue = Tcl_NewStringObj(
	"catch { namespace delete request }\n"
	"namespace eval request { }\n"
	"proc ::request::global { args } { foreach arg $args { uplevel \"::global ::request::$arg\" } }\n", -1);
    Tcl_IncrRefCount(dsc->namespacePrologue);

#if DBG
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Config string = \"%s\"", Tcl_GetStringFromObj(dsc->dtcl_global_init_script, NULL));  /* XXX */
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "Cache size = \"%d\"", *(dsc->cache_size));  /* XXX */
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

    /* This is what happens if it is not set by the user */
    if(*(dsc->cache_size) < 0)
    {
	if (ap_max_requests_per_child != 0)
	    *(dsc->cache_size) = ap_max_requests_per_child / 2;
	else
	    *(dsc->cache_size) = 10; /* Arbitrary number FIXME */
	*(dsc->cache_free) = *(dsc->cache_size);
    } else if (*(dsc->cache_size) > 0) {
	*(dsc->cache_free) = *(dsc->cache_size);
    }
    /* Initializing cache structures */
    dsc->objCacheList = ap_pcalloc(p, *(dsc->cache_size) * sizeof(char *));
    Tcl_InitHashTable(dsc->objCache, TCL_STRING_KEYS);

    sr = s;
    while (sr)
    {
	dtcl_server_conf *mydsc = NULL;
	/* This should set up slave interpreters for other virtual
           hosts */
	if (sr != s) /* not the first one  */
	{
	    mydsc = ap_pcalloc(p, sizeof(dtcl_server_conf));	    
	    ap_set_module_config(sr->module_config, &dtcl_module, mydsc);
	    copy_dtcl_config(p, dsc, mydsc);
	    if (dsc->seperate_virtual_interps != 0)
		mydsc->server_interp = NULL;
	} else {
	    mydsc = (dtcl_server_conf *) ap_get_module_config(sr->module_config, &dtcl_module);
	}
	if (!mydsc->server_interp)
	{
	    mydsc->server_interp = Tcl_CreateSlave(interp, sr->server_hostname, 0);
	    tcl_create_commands(mydsc);
	    Tcl_SetChannelOption(mydsc->server_interp, achan, "-buffering", "none");
	    Tcl_RegisterChannel(mydsc->server_interp, achan);
	}

	mydsc->server_name = ap_pstrdup(p, sr->server_hostname);
	sr = sr->next;
    }
}

MODULE_VAR_EXPORT void dtcl_init_handler(server_rec *s, pool *p)
{
#if THREADED_TCL == 0
    tcl_init_stuff(s, p);
#endif
#ifndef HIDE_DTCL_VERSION
    ap_add_version_component("mod_dtcl/"DTCL_VERSION);
#else
    ap_add_version_component("mod_dtcl");
#endif /* !HIDE_DTCL_VERSION */
}

static const char *set_script(cmd_parms *cmd, dtcl_server_conf *ddc, char *arg, char *arg2)
{
    Tcl_Obj *objarg;
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);

    if (arg == NULL || arg2 == NULL)
	return "Mod_Dtcl Error: Dtcl_Script requires two arguments";

    objarg = Tcl_NewStringObj(arg2, -1);
    Tcl_IncrRefCount(objarg);
    Tcl_AppendToObj(objarg, "\n", 1);
    if (strcmp(arg, "GlobalInitScript") == 0) {
	dsc->dtcl_global_init_script = objarg;
    } else if (strcmp(arg, "ChildInitScript") == 0) {
	dsc->dtcl_child_init_script = objarg;
    } else if (strcmp(arg, "ChildExitScript") == 0) {
	dsc->dtcl_child_exit_script = objarg;
    } else if (strcmp(arg, "BeforeScript") == 0) {
	if (ddc == NULL) {
	    dsc->dtcl_before_script = objarg;
	} else {
	    ddc->dtcl_before_script = objarg;
	}
    } else if (strcmp(arg, "AfterScript") == 0) {
	if (ddc == NULL) {
	    dsc->dtcl_after_script = objarg;
	} else {
	    ddc->dtcl_after_script = objarg;
	}
    } else if (strcmp(arg, "ErrorScript") == 0) {
	if (ddc == NULL)
	    dsc->dtcl_error_script = objarg;
	else
	    ddc->dtcl_error_script = objarg;
    } else {
	return "Mod_Dtcl Error: Dtcl_Script must have a second argument, which is one of: GlobalInitScript, ChildInitScript, ChildExitScript, BeforeScript, AfterScript, ErrorScript";
    }
    return NULL;
}

static const char *set_cachesize(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    *(dsc->cache_size) = strtol(arg, NULL, 10);
    return NULL;
}

static const char *set_uploaddir(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    dsc->upload_dir = arg;
    return NULL;
}

static const char *set_uploadmax(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    dsc->upload_max = strtol(arg, NULL, 10);
    return NULL;
}

static const char *set_filestovar(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    if (!strcmp(arg, "on"))
	dsc->upload_files_to_var = 1;
    else
	dsc->upload_files_to_var = 0;
    return NULL;
}

static const char *set_seperatevirtinterps(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(s->module_config, &dtcl_module);
    if (!strcmp(arg, "on"))
	dsc->seperate_virtual_interps = 1;
    else 
	dsc->seperate_virtual_interps = 0;
    return NULL;
}

/* function to get a config, and merge the directory/server options  */
dtcl_server_conf *dtcl_get_conf(request_rec *r)
{
    dtcl_server_conf *newconfig = NULL;
    dtcl_server_conf *dsc = NULL; /* server config */
    void *dconf = r->per_dir_config;

    dsc = (dtcl_server_conf *) ap_get_module_config(r->server->module_config, &dtcl_module);
    if (dconf != NULL)
    {
	dtcl_server_conf *ddc = (dtcl_server_conf *) 
	    ap_get_module_config(dconf, &dtcl_module); /* per directory config */

	newconfig = (dtcl_server_conf *) ap_pcalloc(r->pool, sizeof(dtcl_server_conf));
	newconfig->server_interp = dsc->server_interp;
	copy_dtcl_config(r->pool, dsc, newconfig);
	/* list here things that can be per-directory  */
	newconfig->dtcl_before_script = ddc->dtcl_before_script ? ddc->dtcl_before_script : dsc->dtcl_before_script;
	newconfig->dtcl_after_script = ddc->dtcl_after_script ? ddc->dtcl_after_script : dsc->dtcl_after_script;
	newconfig->dtcl_error_script = ddc->dtcl_error_script ? ddc->dtcl_error_script : dsc->dtcl_error_script;
	return newconfig;
    }
    return dsc; /* if there is no per dir config, just return the
                   server config */
}

static void copy_dtcl_config(pool *p, dtcl_server_conf *olddsc, dtcl_server_conf *newdsc)
{
    newdsc->server_interp = olddsc->server_interp;
    newdsc->dtcl_global_init_script = olddsc->dtcl_global_init_script;
    newdsc->dtcl_child_init_script = olddsc->dtcl_child_init_script;
    newdsc->dtcl_child_exit_script = olddsc->dtcl_child_exit_script;
    newdsc->dtcl_before_script = olddsc->dtcl_before_script;
    newdsc->dtcl_after_script = olddsc->dtcl_after_script;
    newdsc->dtcl_error_script = olddsc->dtcl_error_script;

    /* these are pointers so that they can be passed around...  */
    newdsc->cache_size = olddsc->cache_size;
    newdsc->cache_free = olddsc->cache_free;
    newdsc->cache_size = olddsc->cache_size;
    newdsc->cache_free = olddsc->cache_free;
    newdsc->upload_max = olddsc->upload_max;
    newdsc->upload_files_to_var = olddsc->upload_files_to_var;
    newdsc->seperate_virtual_interps = olddsc->seperate_virtual_interps;
    newdsc->server_name = olddsc->server_name;
    newdsc->upload_dir = olddsc->upload_dir;
    newdsc->objCacheList = olddsc->objCacheList;
    newdsc->objCache = olddsc->objCache;
    newdsc->namespacePrologue = olddsc->namespacePrologue;

    newdsc->buffer_output = olddsc->buffer_output;
    newdsc->headers_printed = olddsc->headers_printed;
    newdsc->headers_set = olddsc->headers_set;
    newdsc->content_sent = olddsc->content_sent;
    newdsc->obuffer = olddsc->obuffer;
}

static void *create_dtcl_config(pool *p, server_rec *s)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));

    dsc->server_interp = NULL;
    dsc->dtcl_global_init_script = NULL;
    dsc->dtcl_child_init_script = NULL;
    dsc->dtcl_child_exit_script = NULL;
    dsc->dtcl_before_script = NULL;
    dsc->dtcl_after_script = NULL;
    dsc->dtcl_error_script = NULL;

    /* these are pointers so that they can be passed around...  */
    dsc->cache_size = ap_pcalloc(p, sizeof(int));
    dsc->cache_free = ap_pcalloc(p, sizeof(int));
    *(dsc->cache_size) = -1;
    *(dsc->cache_free) = 0;
    dsc->upload_max = 0;
    dsc->upload_files_to_var = 0;
    dsc->seperate_virtual_interps = 0;
    dsc->server_name = NULL;
    dsc->upload_dir = "/tmp";
    dsc->objCacheList = NULL;
    dsc->objCache = ap_pcalloc(p, sizeof(Tcl_HashTable));
    dsc->namespacePrologue = NULL;

    dsc->buffer_output = ap_pcalloc(p, sizeof(int));
    dsc->headers_printed = ap_pcalloc(p, sizeof(int));
    dsc->headers_set = ap_pcalloc(p, sizeof(int));
    dsc->content_sent = ap_pcalloc(p, sizeof(int));
    *(dsc->buffer_output) = 0;
    *(dsc->headers_printed) = 0;
    *(dsc->headers_set) = 0;
    *(dsc->content_sent) = 0;
    dsc->obuffer = ap_pcalloc(p, sizeof(obuff));
    return dsc;
}

void *create_dtcl_dir_config(pool *p, char *dir)
{
    dtcl_server_conf *ddc = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));
    return ddc;
}

void *merge_dtcl_config(pool *p, void *basev, void *overridesv)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_pcalloc(p, sizeof(dtcl_server_conf));
    dtcl_server_conf *base = (dtcl_server_conf *) basev;
    dtcl_server_conf *overrides = (dtcl_server_conf *) overridesv;

    dsc->server_interp = overrides->server_interp ? overrides->server_interp : base->server_interp;

#if 0 /* this stuff should only be done once at the top level  */
    dsc->dtcl_global_init_script = overrides->dtcl_global_init_script ? overrides->dtcl_global_init_script :	base->dtcl_global_init_script;

    dsc->dtcl_child_init_script = overrides->dtcl_child_init_script ? overrides->dtcl_child_init_script : base->dtcl_child_init_script;

    dsc->dtcl_child_exit_script = overrides->dtcl_child_exit_script ? overrides->dtcl_child_exit_script : base->dtcl_child_exit_script;

#endif

    dsc->dtcl_before_script = overrides->dtcl_before_script ? overrides->dtcl_before_script : base->dtcl_before_script;

    dsc->dtcl_after_script = overrides->dtcl_after_script ? overrides->dtcl_after_script : base->dtcl_after_script;

    dsc->dtcl_error_script = overrides->dtcl_error_script ? overrides->dtcl_error_script : base->dtcl_error_script;

/*     dsc->cache_size = overrides->cache_size ? overrides->cache_size : base->cache_size;
    dsc->cache_free = overrides->cache_free ? overrides->cache_free : base->cache_free;  */
    dsc->upload_max = overrides->upload_max ? overrides->upload_max : base->upload_max;

    dsc->server_name = overrides->server_name ? overrides->server_name : base->server_name;
    dsc->upload_dir = overrides->upload_dir ? overrides->upload_dir : base->upload_dir;

    return dsc;
}

void dtcl_child_init(server_rec *s, pool *p)
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

void dtcl_child_exit(server_rec *s, pool *p)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *) ap_get_module_config(s->module_config, &dtcl_module);

    if (dsc->dtcl_child_exit_script != NULL)
	if (Tcl_EvalObjEx(dsc->server_interp, dsc->dtcl_child_exit_script, 0) != TCL_OK)
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "Problem running child exit script: %s", Tcl_GetStringFromObj(dsc->dtcl_child_exit_script, NULL));
}

const handler_rec dtcl_handlers[] =
{
    {"application/x-httpd-tcl", send_content},
    {"application/x-dtcl-tcl", send_content},
    {NULL}
};

const command_rec dtcl_cmds[] =
{
    {"Dtcl_Script", set_script, NULL, OR_FILEINFO, TAKE2, "Dtcl_Script GlobalInitScript|ChildInitScript|ChildExitScript|BeforeScript|AfterScript|ErrorScript \"tcl source code\""},
    {"Dtcl_CacheSize", set_cachesize, NULL, RSRC_CONF, TAKE1, "Dtcl_Cachesize cachesize"},
    {"Dtcl_UploadDirectory", set_uploaddir, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadDirectory dirname"},
    {"Dtcl_UploadMaxSize", set_uploadmax, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadMaxSize size"},
    {"Dtcl_UploadFilesToVar", set_filestovar, NULL, RSRC_CONF, TAKE1, "Dtcl_UploadFilesToVar on/off"},
    {"Dtcl_SeperateVirtualInterps", set_seperatevirtinterps, NULL, RSRC_CONF, TAKE1, "Dtcl_SeperateVirtualInterps on/off"},
    {NULL}
};

module MODULE_VAR_EXPORT dtcl_module =
{
    STANDARD_MODULE_STUFF,
    dtcl_init_handler,		/* initializer */
    create_dtcl_dir_config,	/* dir config creater */
    NULL,                       /* dir merger --- default is to override */
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
