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
#include "apache_request.h"
#include "apache_cookie.h"
#include "mod_dtcl.h"

#define BUFSZ 4096

extern module dtcl_module;

extern Tcl_Obj *uploadstorage[];

#define POOL (globals->r->pool)

/* Make a self-referencing URL  */

int MakeURL(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "filename");
	return TCL_ERROR;
    }
    Tcl_SetResult(interp, ap_construct_url(POOL, Tcl_GetString(objv[1]), globals->r), NULL);
    return TCL_OK;
}

/* Include and parse a file */

int Parse(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *filename;
    struct stat finfo;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "filename");
	return TCL_ERROR;
    }

    filename = Tcl_GetStringFromObj (objv[1], (int *)NULL);
    if (!strcmp(filename, globals->r->filename))
    {
	Tcl_AddErrorInfo(interp, "Cannot recursively call the same file!");
	return TCL_ERROR;
    }

    if (stat(filename, &finfo))
    {
	Tcl_AddErrorInfo(interp, Tcl_PosixError(interp));
	return TCL_ERROR;
    }
    if (get_parse_exec_file(globals->r, dsc, filename, 0) == TCL_OK)
	return TCL_OK;
    else
	return TCL_ERROR;
}

/* Tcl command to include flat files */

int Include(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Channel fd;
    int sz;
    char buf[BUFSZ];
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc =
	(dtcl_server_conf *)ap_get_module_config(globals->r->server->module_config,
						 &dtcl_module);
    Tcl_Obj *outobj;

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "filename");
	return TCL_ERROR;
    }

    fd = Tcl_OpenFileChannel(interp,
			     Tcl_GetStringFromObj(objv[1], (int *)NULL), "r", 0664);

    if (fd == NULL)
    {
        return TCL_ERROR;
    } else {
	Tcl_SetChannelOption(interp, fd, "-translation", "lf");
    }
/*     print_headers(globals->r);
       flush_output_buffer(globals->r);  */

    outobj = Tcl_NewObj();
    Tcl_IncrRefCount(outobj);
    while ((sz = Tcl_ReadChars(fd, outobj, BUFSZ - 1, 0)))
    {
	if (sz == -1)
	{
	    Tcl_AddErrorInfo(interp, Tcl_PosixError(interp));
	    Tcl_DecrRefCount(outobj);
	    return TCL_ERROR;
	}

	buf[sz] = '\0';

        /* we could include code to either ap_pwrite this or memwrite
           it, depending on buffering */
	Tcl_WriteObj(*(dsc->outchannel), outobj);

	if (sz < BUFSZ - 1)
	    break;
    }
    Tcl_DecrRefCount(outobj);
    return Tcl_Close(interp, fd);
}

/* Command to *only* add to the output buffer */

int Buffer_Add(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }
    Tcl_WriteObj(*(dsc->outchannel), objv[1]);
    *(dsc->content_sent) = 0;
    return TCL_OK;
}

/* Tcl command to output some text to the web server  */

int Hputs(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *arg1;
    int length;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	return TCL_ERROR;
    }

    arg1 = Tcl_GetStringFromObj(objv[1], &length);

    if (!strncmp("-error", arg1, 6))
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	    return TCL_ERROR;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
		     globals->r->server, "Mod_Dtcl Error: %s",
		     Tcl_GetStringFromObj (objv[2], (int *)NULL));
    } else {
	Tcl_DString outstring;
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 1, objv, "?-error? string");
	    return TCL_ERROR;
	}
	/* transform it from UTF to External representation */
	Tcl_UtfToExternalDString(NULL, arg1, length, &outstring);
 	arg1 = Tcl_DStringValue(&outstring);
	length = Tcl_DStringLength(&outstring);
	if (*(dsc->buffer_output) == 1)
	{
	    Tcl_DStringAppend(dsc->buffer, arg1, length);
	} else {
	    print_headers(globals->r);
	    flush_output_buffer(globals->r);
	    ap_rwrite(arg1, length, globals->r);
	}
	Tcl_DStringFree(&outstring);
    }

    return TCL_OK;
}

/* Tcl command to manipulate headers */

int Headers(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *opt;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc < 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "option arg ?arg ...?");
	return TCL_ERROR;
    }
    if (*(dsc->headers_printed) != 0)
    {
	Tcl_AddObjErrorInfo(interp, "Cannot manipulate headers - already sent", -1);
	return TCL_ERROR;
    }
    opt = Tcl_GetStringFromObj(objv[1], NULL);

    if (!strcmp("setcookie", opt)) /* ### setcookie ### */
    {
	int i;
	ApacheCookie *cookie;
	char *stringopts[12] = {NULL, NULL, NULL, NULL, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL, NULL};

	if (objc < 4 || objc > 14)
	{
	    Tcl_WrongNumArgs(interp, 2, objv,
			     "-name cookie-name -value cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure on/off?");
	    return TCL_ERROR;
	}

	/* SetCookie: foo=bar; EXPIRES=DD-Mon-YY HH:MM:SS; DOMAIN=domain; PATH=path; SECURE */

	for (i = 0; i < objc - 2; i++)
	{
	    stringopts[i] = Tcl_GetString(objv[i + 2]);
	}
	cookie = ApacheCookie_new(globals->r,
				  stringopts[0], stringopts[1],
				  stringopts[2], stringopts[3],
				  stringopts[4], stringopts[5],
				  stringopts[6], stringopts[7],
				  stringopts[8], stringopts[9],
				  stringopts[10], stringopts[11],
				  NULL);
	ApacheCookie_bake(cookie);
    }
    else if (!strcmp("redirect", opt)) /* ### redirect ### */
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "new-url");
	    return TCL_ERROR;
	}
	ap_table_set(globals->r->headers_out, "Location",
		     Tcl_GetStringFromObj (objv[2], (int *)NULL));
	globals->r->status = 301;
	return TCL_RETURN;
    }
    else if (!strcmp("set", opt)) /* ### set ### */
    {
	if (objc != 4)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "headername value");
	    return TCL_ERROR;
	}
	ap_table_set(globals->r->headers_out,
		     Tcl_GetStringFromObj (objv[2], (int *)NULL),
		     Tcl_GetStringFromObj (objv[3], (int *)NULL));
    }
    else if (!strcmp("type", opt)) /* ### set ### */
    {
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "mime/type");
	    return TCL_ERROR;
	}
	set_header_type(globals->r, Tcl_GetStringFromObj(objv[2], (int *)NULL));
    } else if (!strcmp("numeric", opt)) /* ### numeric ### */
    {
	int st = 200;

	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "response code");
	    return TCL_ERROR;
	}
	if (Tcl_GetIntFromObj(interp, objv[2], &st) != TCL_ERROR)
	    globals->r->status = st;
	else
	    return TCL_ERROR;
    } else {
	/* XXX	Tcl_WrongNumArgs(interp, 1, objv, "headers option arg ?arg ...?");  */
	return TCL_ERROR;
    }
    return TCL_OK;
}

/* turn buffering on and off */

int Buffered(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *opt = NULL;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc != 2)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "on/off");
	return TCL_ERROR;
    }
    opt = Tcl_GetStringFromObj(objv[1], NULL);
    if (!strncmp(opt, "on", 2))
    {
	*(dsc->buffer_output) = 1;
    } else if (!strncmp(opt, "off", 3)) {
	*(dsc->buffer_output) = 0;
	print_headers(globals->r);
	flush_output_buffer(globals->r);
    } else {
	return TCL_ERROR;
    }
    return TCL_OK;
}
/* Tcl command to flush the output stream */

int HFlush(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);

    if (objc != 1)
    {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }
    print_headers(globals->r);
    flush_output_buffer(globals->r);
    ap_rflush(globals->r);
    return TCL_OK;
}

/* Tcl command to get and parse any CGI and environmental variables */

/* Get the environmental variables, but do it from a tcl function, so
   we can decide whether we wish to or not */

int HGetVars(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *timefmt = DEFAULT_TIME_FORMAT;
#ifndef WIN32
    struct passwd *pw;
#endif /* ndef WIN32 */
    char *t;
    char *authorization = NULL;

    time_t date;

    int i;

    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);

    array_header *hdrs_arr;
    table_entry *hdrs;
    array_header *env_arr;
    table_entry  *env;
    Tcl_Obj *EnvsObj = NULL;
#if HEADERS_IN_ENVS == 0
	Tcl_Obj *ClientEnvsObj = NULL;
#endif

    EnvsObj = Tcl_NewStringObj("::request::ENVS", -1);
    Tcl_IncrRefCount(EnvsObj);
#if HEADERS_IN_ENVS == 0
	ClientEnvsObj = Tcl_NewStringObj("::request::CLIENT_ENVS", -1);
    Tcl_IncrRefCount(ClientEnvsObj);
#endif
    date = globals->r->request_time;

    /* retrieve cgi variables */
    ap_add_cgi_vars(globals->r);
    ap_add_common_vars(globals->r);

    hdrs_arr = ap_table_elts(globals->r->headers_in);
    hdrs = (table_entry *) hdrs_arr->elts;

    env_arr =  ap_table_elts(globals->r->subprocess_env);
    env     = (table_entry *) env_arr->elts;

    /* Get the user/pass info for Basic authentication */
    (const char*)authorization = ap_table_get(globals->r->headers_in, "Authorization");
    if (authorization && !strcasecmp(ap_getword_nc(POOL, &authorization, ' '), "Basic"))
    {
	char *tmp;
	char *user;
	char *pass;

	tmp = ap_pbase64decode(POOL, authorization);
	user = ap_getword_nulls_nc(POOL, &tmp, ':');
	pass = tmp;
 	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::request::USER", -1),
		       Tcl_NewStringObj("user", -1),
		       STRING_TO_UTF_TO_OBJ(user, POOL),
		       0);
 	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::request::USER", -1),
		       Tcl_NewStringObj("pass", -1),
		       STRING_TO_UTF_TO_OBJ(pass, POOL),
		       0);
    }

    /* These were the "include vars"  */
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DATE_LOCAL", -1),
		   STRING_TO_UTF_TO_OBJ(ap_ht_time(POOL, date, timefmt, 0), POOL), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DATE_GMT", -1),
		   STRING_TO_UTF_TO_OBJ(ap_ht_time(POOL, date, timefmt, 1), POOL), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("LAST_MODIFIED", -1),
		   STRING_TO_UTF_TO_OBJ(ap_ht_time(POOL, globals->r->finfo.st_mtime, timefmt, 0), POOL), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_URI", -1),
		   STRING_TO_UTF_TO_OBJ(globals->r->uri, POOL), 0);
    Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_PATH_INFO", -1),
		   STRING_TO_UTF_TO_OBJ(globals->r->path_info, POOL), 0);

#ifndef WIN32
    pw = getpwuid(globals->r->finfo.st_uid);
    if (pw)
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("USER_NAME", -1),
		       STRING_TO_UTF_TO_OBJ(ap_pstrdup(POOL, pw->pw_name), POOL), 0);
    else
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("USER_NAME", -1),
		       STRING_TO_UTF_TO_OBJ(
			   ap_psprintf(POOL, "user#%lu",
				       (unsigned long) globals->r->finfo.st_uid), POOL), 0);
#endif

    if ((t = strrchr(globals->r->filename, '/')))
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_NAME", -1),
		       STRING_TO_UTF_TO_OBJ(++t, POOL), 0);
    else
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("DOCUMENT_NAME", -1),
		       STRING_TO_UTF_TO_OBJ(globals->r->uri, POOL), 0);

    if (globals->r->args)
    {
	char *arg_copy = ap_pstrdup(POOL, globals->r->args);
	ap_unescape_url(arg_copy);
	Tcl_ObjSetVar2(interp, EnvsObj, Tcl_NewStringObj("QUERY_STRING_UNESCAPED", -1),
		       STRING_TO_UTF_TO_OBJ(ap_escape_shell_cmd(POOL, arg_copy), POOL), 0);
    }

    /* ----------------------------  */

    /* transfer client request headers to TCL request namespace */
    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
	if (!hdrs[i].key)
	    continue;
	else {
#if HEADERS_IN_ENVS == 0
		Tcl_ObjSetVar2(interp, ClientEnvsObj, STRING_TO_UTF_TO_OBJ(hdrs[i].key, POOL),
			   STRING_TO_UTF_TO_OBJ(hdrs[i].val, POOL), 0);
#else
	    Tcl_ObjSetVar2(interp, EnvsObj, STRING_TO_UTF_TO_OBJ(hdrs[i].key, POOL),
			   STRING_TO_UTF_TO_OBJ(hdrs[i].val, POOL), 0);
#endif
	}
    }

    /* transfer apache internal cgi variables to TCL request namespace */
    for (i = 0; i < env_arr->nelts; ++i)
    {
	if (!env[i].key)
	    continue;
	Tcl_ObjSetVar2(interp, EnvsObj, STRING_TO_UTF_TO_OBJ(env[i].key, POOL),
		       STRING_TO_UTF_TO_OBJ(env[i].val, POOL), 0);
    }

    do { /* I do this because I want some 'local' variables */
	ApacheCookieJar *cookies = ApacheCookie_parse(globals->r, NULL);
	Tcl_Obj *cookieobj = Tcl_NewStringObj("::request::COOKIES", -1);

	for (i = 0; i < ApacheCookieJarItems(cookies); i++) {
	    ApacheCookie *c = ApacheCookieJarFetch(cookies, i);
	    int j;
	    for (j = 0; j < ApacheCookieItems(c); j++) {
		char *name = c->name;
		char *value = ApacheCookieFetch(c, j);
		Tcl_ObjSetVar2(interp, cookieobj,
			       Tcl_NewStringObj(name, -1),
			       Tcl_NewStringObj(value, -1), 0);
/* 			       STRING_TO_UTF_TO_OBJ(name, POOL),
			       STRING_TO_UTF_TO_OBJ(value, POOL), 0);  */
	    }

	}
    } while (0);

    /* cleanup system cgi variables */
    ap_clear_table(globals->r->subprocess_env);

    return TCL_OK;
}

/* Tcl command to return a particular variable.  */

/* Use:
   var get foo
   var list foo
   var names
   var number
   var all
  */

int Var(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *command;
    int i;
    Tcl_Obj *result = NULL;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    array_header *parmsarray = ap_table_elts(globals->req->parms);
    table_entry *parms = (table_entry *)parmsarray->elts;

    if (objc < 2 || objc > 3)
    {
	Tcl_WrongNumArgs(interp, 1, objv,
			 "(get varname|list varname|exists varname|names|number|all)");
	return TCL_ERROR;
    }
    command = Tcl_GetString(objv[1]);

    if (!strcmp(command, "get"))
    {
	char *key = NULL;
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "variablename");
	    return TCL_ERROR;
	}
	key = Tcl_GetStringFromObj(objv[2], NULL);

        /* This isn't real efficient - move to hash table later
           on... */
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    if (!strncmp(key, StringToUtf(parms[i].key, POOL),
			 strlen(key) < strlen(parms[i].key) ?
			 strlen(parms[i].key) : strlen(key)))
	    {
		/* The following makes sure that we get one string,
                   with no sub lists. */
		if (result == NULL)
		{
		    result = STRING_TO_UTF_TO_OBJ(parms[i].val, POOL);
		    Tcl_IncrRefCount(result);
		} else {
		    Tcl_Obj *tmpobjv[2];
		    tmpobjv[0] = result;
		    tmpobjv[1] = STRING_TO_UTF_TO_OBJ(parms[i].val, POOL);
		    result = Tcl_ConcatObj(2, tmpobjv);
		}
	    }
	}

	if (result == NULL)
	    Tcl_AppendResult(interp, "", NULL);
	else
	    Tcl_SetObjResult(interp, result);
    } else if(!strcmp(command, "exists")) {
	char *key;
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "variablename");
	    return TCL_ERROR;
	}
	key = Tcl_GetString(objv[2]);

        /* This isn't real efficient - move to hash table later on. */
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    if (!strncmp(key, StringToUtf(parms[i].key, POOL),
			 strlen(key) < strlen(parms[i].key) ?
			 strlen(parms[i].key) : strlen(key)))
	    {
		result = Tcl_NewIntObj(1);
		Tcl_IncrRefCount(result);
	    }
	}

	if (result == NULL)
	    Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
	else
	    Tcl_SetObjResult(interp, result);

    } else if(!strcmp(command, "list")) {
	char *key;
	if (objc != 3)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "variablename");
	    return TCL_ERROR;
	}
	key = Tcl_GetStringFromObj(objv[2], NULL);

        /* This isn't real efficient - move to hash table later on. */
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    if (!strncmp(key, StringToUtf(parms[i].key, POOL), 
			 strlen(key) < strlen(parms[i].key) ?
			 strlen(parms[i].key) : strlen(key)))
	    {
		if (result == NULL)
		{
		    result = Tcl_NewObj();
		    Tcl_IncrRefCount(result);
		}
		Tcl_ListObjAppendElement(interp, result,
					 STRING_TO_UTF_TO_OBJ(parms[i].val, POOL));
	    }
	}

	if (result == NULL)
	    Tcl_AppendResult(interp, "", NULL);
	else
	    Tcl_SetObjResult(interp, result);
    } else if(!strcmp(command, "names")) {
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, NULL);
	    return TCL_ERROR;
	}
	result = Tcl_NewObj();
	Tcl_IncrRefCount(result);
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    Tcl_ListObjAppendElement(interp, result,
				     STRING_TO_UTF_TO_OBJ(parms[i].key, POOL));
	}

	if (result == NULL)
	    Tcl_AppendResult(interp, "", NULL);
	else
	    Tcl_SetObjResult(interp, result);

    } else if(!strcmp(command, "number")) {
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, NULL);
	    return TCL_ERROR;
	}

	result = Tcl_NewIntObj(parmsarray->nelts);
	Tcl_IncrRefCount(result);
	Tcl_SetObjResult(interp, result);
    } else if(!strcmp(command, "all")) {
	if (objc != 2)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, NULL);
	    return TCL_ERROR;
	}
	result = Tcl_NewObj();
	Tcl_IncrRefCount(result);
	for (i = 0; i < parmsarray->nelts; ++i)
	{
	    Tcl_ListObjAppendElement(interp, result,
				     STRING_TO_UTF_TO_OBJ(parms[i].key, POOL));
	    Tcl_ListObjAppendElement(interp, result,
				     STRING_TO_UTF_TO_OBJ(parms[i].val, POOL));
	}

	if (result == NULL)
	    Tcl_AppendResult(interp, "", NULL);
	else
	    Tcl_SetObjResult(interp, result);


    } else {
	/* bad command  */
	Tcl_AddErrorInfo(interp, "bad option: must be one of 'get, list, names, number, all'");
	return TCL_ERROR;
    }

    return TCL_OK;
}

/*
upload get XYZ
               channel        # returns channel
	       save (name)    # returns name?
	       data           # returns data

with the third one reporting an error if this hasn't been enabled, or
the first two if it has.

upload info XYZ

                exists
                size
                type
                filename

upload names

gets all the upload names.
*/

int Upload(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *command = NULL;
    Tcl_Obj *result = NULL;
    ApacheUpload *upload;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (objc < 2 || objc > 5)
    {
	Tcl_WrongNumArgs(interp, 1, objv, "get ...|info ...|names");
	return TCL_ERROR;
    }
    command = Tcl_GetString(objv[1]);

    result = Tcl_NewObj();
    if (!strcmp(command, "get"))
    {
	char *varname = NULL;
	if (objc < 4)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "varname channel|save filename|var varname");
	    return TCL_ERROR;
	}
	varname = Tcl_GetString(objv[2]);
	upload = ApacheUpload_find(globals->req->upload, varname);
	if (upload != NULL) /* make sure we have an upload */
	{
	    Tcl_Channel chan;
	    char *method = Tcl_GetString(objv[3]);
	    if (!strcmp(method, "channel"))
	    {
		if (ApacheUpload_FILE(upload) != NULL)
		{
		    /* create and return a file channel */
		    char *channelname = NULL;
#ifdef __MINGW32__
		    chan = Tcl_MakeFileChannel(
			(ClientData)_get_osfhandle(
			    fileno(ApacheUpload_FILE(upload))), TCL_READABLE);
#else
		    chan = Tcl_MakeFileChannel(
			(ClientData)fileno(ApacheUpload_FILE(upload)), TCL_READABLE);
#endif
		    Tcl_RegisterChannel(interp, chan);
		    channelname = (char *)Tcl_GetChannelName(chan);
		    Tcl_SetStringObj(result, channelname, -1);
		}
	    } else if (!strcmp(method, "save")) {
		/* save data to a specified filename  */

		int sz;
		char savebuffer[BUFSZ];
		Tcl_Channel savechan = NULL;
		Tcl_Channel chan = NULL;
		if (objc != 5)
		{
		    Tcl_WrongNumArgs(interp, 4, objv, "filename");
		    return TCL_ERROR;
		}

		savechan = Tcl_OpenFileChannel(interp, Tcl_GetString(objv[4]), "w", 0600);
		if (savechan == NULL)
		    return TCL_ERROR;
		else
		    Tcl_SetChannelOption(interp, savechan, "-translation", "binary");

#ifdef __MINGW32__
		chan = Tcl_MakeFileChannel(
		    (ClientData)_get_osfhandle(
			fileno(ApacheUpload_FILE(upload))), TCL_READABLE);
#else
		chan = Tcl_MakeFileChannel(
		    (ClientData)fileno(ApacheUpload_FILE(upload)), TCL_READABLE);
#endif
		Tcl_SetChannelOption(interp, chan, "-translation", "binary");

		while ((sz = Tcl_Read(chan, savebuffer, BUFSZ)))
		{
		    if (sz == -1)
		    {
			Tcl_AddErrorInfo(interp, Tcl_PosixError(interp));
			return TCL_ERROR;
		    }

		    Tcl_Write(savechan, savebuffer, sz);
		    if (sz < 4096)
			break;
		}
		Tcl_Close(interp, savechan);
		Tcl_SetIntObj(result, 1);
	    } else if (!strcmp(method, "data")) {
		/* this sucks - we should use the hook, but I want to
                   get everything fixed and working first */
		if (dsc->upload_files_to_var)
		{
		    char *bytes = NULL;
		    Tcl_Channel chan = NULL;

		    bytes = Tcl_Alloc((unsigned int)ApacheUpload_size(upload));
#ifdef __MINGW32__
		    chan = Tcl_MakeFileChannel(
			(ClientData)_get_osfhandle(
			    fileno(ApacheUpload_FILE(upload))), TCL_READABLE);
#else
		    chan = Tcl_MakeFileChannel(
			(ClientData)fileno(ApacheUpload_FILE(upload)), TCL_READABLE);
#endif
		    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
		    Tcl_SetChannelOption(interp, chan, "-encoding", "binary");
		    /* put data in a variable  */
		    Tcl_ReadChars(chan, result, ApacheUpload_size(upload), 0);
		} else {
		    Tcl_AppendResult(interp, "Dtcl_UploadFilesToVar is not set", NULL);
		    return TCL_ERROR;
		}
	    }
	} else {
	    /* no variable found  */
	    Tcl_SetStringObj(result, "", -1);
	}
    } else if (!strcmp(command, "info")) {
	char *varname = NULL;
	char *infotype = NULL;
	if (objc != 4)
	{
	    Tcl_WrongNumArgs(interp, 2, objv, "varname exists|size|type|filename");
	    return TCL_ERROR;
	}
	varname = Tcl_GetString(objv[2]);
	infotype = Tcl_GetString(objv[3]);

	upload = ApacheUpload_find(globals->req->upload, varname);
	if (upload != NULL)
	{
	    if (!strcmp(infotype, "exists"))
	    {
		Tcl_SetIntObj(result, 1);
	    } else if (!strcmp(infotype, "size")) {
		Tcl_SetIntObj(result, ApacheUpload_size(upload));
	    } else if (!strcmp(infotype, "type")) {
		char *type = NULL;
		type = (char *)ApacheUpload_type(upload);
		if (type)
		    Tcl_SetStringObj(result, type, -1);
		else
		    Tcl_SetStringObj(result, "", -1);
	    } else if (!strcmp(infotype, "filename")) {
		Tcl_SetStringObj(result, StringToUtf(upload->filename, POOL), -1);
	    } else {
		Tcl_AddErrorInfo(interp, "unknown upload info command, should be exists|size|type|filename");
		return TCL_ERROR;
	    }
	} else {
	    if (!strcmp(infotype, "exists")) {
		Tcl_SetIntObj(result, 0);
	    } else {
		Tcl_AddErrorInfo(interp, "variable doesn't exist");
		return TCL_ERROR;
	    }
	}
    } else if (!strcmp(command, "names")) {
	upload = ApacheRequest_upload(globals->req);
	while (upload)
	{
	    Tcl_ListObjAppendElement(interp, result,
				     STRING_TO_UTF_TO_OBJ(upload->name, POOL));
	    upload = upload->next;
	}
    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "upload get|info|names");
	return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}


/* Tcl command to get, and print some information about the current
   state of affairs */

int Dtcl_Info(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *tble;
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    tble = ap_psprintf(POOL,
		       "<table border=0 bgcolor=green><tr><td>\n"
		       "<table border=0 bgcolor=\"#000000\">\n"
		       "<tr><td align=center bgcolor=blue><font color=\"#ffffff\" size=\"+2\">dtcl_info</font><br></td></tr>\n"
		       "<tr><td><font color=\"#ffffff\">Free cache size: %d</font><br></td></tr>\n"
		       "<tr><td><font color=\"#ffffff\">PID: %d</font><br></td></tr>\n"
		       "</table>\n"
		       "</td></tr></table>\n", *(dsc->cache_free), getpid());
/*     print_headers(globals->r);
       flush_output_buffer(globals->r);  */
    Tcl_WriteObj(*(dsc->outchannel), Tcl_NewStringObj(tble, -1));
    return TCL_OK;
}

/* Tcl command to erase body, so that only header is returned.
   Necessary for 304 responses */

int No_Body(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{

    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    dtcl_server_conf *dsc = (dtcl_server_conf *)
	ap_get_module_config(globals->r->server->module_config, &dtcl_module);

    if (*(dsc->content_sent) == 1)
	return TCL_ERROR;

    print_headers(globals->r);
    Tcl_DStringInit(dsc->buffer);
    return TCL_OK;
}
