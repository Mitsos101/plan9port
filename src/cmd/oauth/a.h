#include <u.h>
#include <errno.h>
#include <ctype.h>
#include <libc.h>
#include <libsec.h>

#define USER_AGENT    "oauthtest"

void*	emalloc(int);
void*	erealloc(void*, int);
char*	estrdup(char*);
int	urlencodefmt(Fmt*);

// JSON parser, from 9front

typedef struct JSONEl JSONEl;
typedef struct JSON JSON;

#pragma varargck type "J" JSON*

enum {
	JSONNull,
	JSONBool,
	JSONNumber,
	JSONString,
	JSONArray,
	JSONObject,
};

struct JSONEl {
	char *name;
	JSON *val;
	JSONEl *next;
};

struct JSON
{
	int t;
	union {
		double n;
		char *s;
		JSONEl *first;
	};
};

JSON*	jsonparse(char *);
void	jsonfree(JSON *);
JSON*	jsonbyname(JSON *, char *);
char*	jsonstr(JSON *);
int	JSONfmt(Fmt*);
void	JSONfmtinstall(void);


// Wrapper to hide whether we're using OpenSSL or macOS' libNetwork for HTTPS.

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

char *httpreq(Protocol *proto, char *host, char *request, HTTPHeader *hdr);

// JSON RPC

enum
{
	MaxResponse = 1<<29,
};

JSON*	urlpost(char *s, char *name1, ...);
JSON*	urlget(char *s);


enum
{
	STACKSIZE = 32768
};

// URL parser
enum {
	Domlen = 256,
};

typedef struct Url Url;
struct Url
{
	char	*scheme;
	char	*user;
	char	*pass;
	char	*host;
	char	*port;
	char	*path;
	char	*query;
	char	*fragment;
};


char*	Upath(Url *);
Url*	url(char *s);
Url*	saneurl(Url *u);
void	freeurl(Url *u);

// SHA256

enum
{
	SHA2_256dlen=	32,	/* SHA-256 digest length */
};

void*	sha2_256(uchar*, ulong, uchar*, void*);

// idn

int	idn2utf(char *name, char *buf, int nbuf);
