#include <u.h>
#include <errno.h>
#include <libc.h>
#include <libsec.h>

#define USER_AGENT    "oauthtest"

void*	emalloc(int);
void*	erealloc(void*, int);
char*	estrdup(char*);
int	urlencodefmt(Fmt*);

// JSON parser

typedef struct Json Json;

enum
{
	Jstring,
	Jnumber,
	Jobject,
	Jarray,
	Jtrue,
	Jfalse,
	Jnull
};

struct Json
{
	int ref;
	int type;
	char *string;
	double number;
	char **name;
	Json **value;
	int len;
};

void	jclose(Json*);
Json*	jincref(Json*);
vlong	jint(Json*);
Json*	jlookup(Json*, char*);
double	jnumber(Json*);
int	jsonfmt(Fmt*);
int	jstrcmp(Json*, char*);
char*	jstring(Json*);
Json*	jwalk(Json*, char*);
Json*	parsejson(char*);


// Wrapper to hide whether we're using OpenSSL for HTTPS.

typedef struct Protocol Protocol;
typedef struct Pfd Pfd;
struct Protocol
{
	Pfd *(*connect)(char *host);
	int (*read)(Pfd*, void*, int);
	int (*write)(Pfd*, void*, int);
	void (*close)(Pfd*);
};

Protocol https;


// HTTP library

typedef struct HTTPHeader HTTPHeader;
struct HTTPHeader
{
	int code;
	char proto[100];
	char codedesc[100];
	vlong contentlength;
	char contenttype[100];
};

char *httpreq(Protocol *proto, char *host, char *request, HTTPHeader *hdr, int rfd, vlong rlength);

// JSON RPC

enum
{
	MaxResponse = 1<<29,
};

Json*	jsonrpc(Protocol *proto, char *host, char *path, char *method, char *name1, va_list arg, int usecache);

enum
{
	STACKSIZE = 32768
};
