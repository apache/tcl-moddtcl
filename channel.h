/* Functions for mod_dtcl Tcl output channel .*/

#include "mod_dtcl.h"

extern int closeproc(ClientData, Tcl_Interp *);
extern int inputproc(ClientData, char *, int, int *);
extern int outputproc(ClientData, char *, int, int *);
extern int setoptionproc(ClientData, Tcl_Interp *, char *, char *);
/* extern int getoptionproc(ClientData, Tcl_Interp *, char *, Tcl_DString *); */
extern void watchproc(ClientData, int);
extern int gethandleproc(ClientData, int, ClientData *);

extern Tcl_ChannelType ApacheChan;

