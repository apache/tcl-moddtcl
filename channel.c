#include "httpd.h"
#include "http_config.h"
#include "http_request.h"

#include <tcl.h>
#include <errno.h>

#include "apache_request.h"
#include "mod_dtcl.h"

/* This file describes the mod_dtcl Tcl output channel. */

static int inputproc(ClientData instancedata, char *buf, int toRead, int *errorCodePtr)
{
    return EINVAL;
}

/* This is the output 'method' for the Memory Buffer Tcl 'File'
   Channel that we create to divert stdout to */

static int outputproc(ClientData instancedata, char *buf, int toWrite, int *errorCodePtr)
{
    dtcl_server_conf *dsc = (dtcl_server_conf *)instancedata;
    Tcl_DStringAppend(dsc->buffer, buf, toWrite);
    return toWrite;
}

static int closeproc(ClientData instancedata, Tcl_Interp *interp)
{
    dtcl_interp_globals *globals = Tcl_GetAssocData(interp, "dtcl", NULL);
    print_headers(globals->r);
    flush_output_buffer(globals->r);
    return 0;
}

static int setoptionproc(ClientData instancedata, Tcl_Interp *interp,
			 char *optionname, char *value)
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

Tcl_ChannelType ApacheChan = {
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

