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


extern request_rec *global_rr;
extern obuff obuffer;
extern int content_sent;
extern int buffer_output;
extern int headers_printed;
extern int cacheFreeSize;

/* Include and parse a file */

int Parse(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int Include(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int Buffer_Add(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int Hputs(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int Headers(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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
	int i;
	ApacheCookie *cookie;
	char *stringopts[12] = {NULL, NULL, NULL, NULL, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL, NULL};

	if (objc < 4 || objc > 14)
	{
	    Tcl_WrongNumArgs(interp, 1, objv,
			     "headers setcookie -name cookie-name -value cookie-value ?-expires expires? ?-domain domain? ?-path path? ?-secure on/off?");
	    return TCL_ERROR;
	}

	/* SetCookie: foo=bar; EXPIRES=DD-Mon-YY HH:MM:SS; DOMAIN=domain; PATH=path; SECURE */

	for (i = 0; i < objc - 2; i++)
	{
	    stringopts[i] = Tcl_GetString(objv[i + 2]);
	}
	cookie = ApacheCookie_new(global_rr,
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

int Buffered(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int HFlush(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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

int HGetVars(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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
    Tcl_IncrRefCount(EnvsObj);
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

    /* transfer client request headers to TCL request namespace */
    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
	if (!hdrs[i].key)
	    continue;
	else {
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

    do { /* I do this because I want some 'local' variables */
	ApacheCookieJar *cookies = ApacheCookie_parse(global_rr, NULL);
	Tcl_Obj *cookieobj = Tcl_NewStringObj("::request::COOKIES", -1);

	for (i = 0; i < ApacheCookieJarItems(cookies); i++) {
	    ApacheCookie *c = ApacheCookieJarFetch(cookies, i);
	    int j;
	    for (j = 0; j < ApacheCookieItems(c); j++) {
		char *name = c->name;
		char *value = ApacheCookieFetch(c, j);
		Tcl_ObjSetVar2(interp, cookieobj, 
			       STRING_TO_UTF_TO_OBJ(name),
			       STRING_TO_UTF_TO_OBJ(value), 0);
	    }
	    
	} 
    } while (0);
	    
    /* cleanup system cgi variables */
    ap_clear_table(global_rr->subprocess_env);

    return TCL_OK;
}

/* Tcl command to get, and print some information about the current
   state of affairs */

int Dtcl_Info(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
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
