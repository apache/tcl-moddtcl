#ifndef MOD_DTCL_H
#define MOD_DTCL_H 1

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

typedef struct {
    char *buf;
    int len;
} obuff;

int memwrite(obuff *, char *, int);
int send_content(request_rec *);
int send_parsed_file(request_rec *, char *, struct stat*, int);
int send_tcl_file(request_rec *, char *, struct stat*);
int set_header_type(request_rec *, char *);
int print_headers(request_rec *);
int print_error(request_rec *, int, char *);
int flush_output_buffer(request_rec *);
void tcl_init_stuff(server_rec *s, pool *p);

char *StringToUtf(char *input);

/* Macro to Tcl Objectify StringToUtf stuff */
#define STRING_TO_UTF_TO_OBJ(string) Tcl_NewStringObj(StringToUtf(string), -1)

#endif
