#include "a.h"

enum
{
	Verifierlen = 128,
	Statelen = 32,
};

typedef struct Elem Elem;
struct Elem
{
	char *name;
	int type;
	long off;
};

typedef struct Discovery Discovery;
struct Discovery
{
	char *authorization_endpoint;
	char *token_endpoint;
}

static Elem discelems[] =
{
	{"authorization_endpoint", JSONString, offsetof(Discovery, authorization_endpoint)},
	{"token_endpoint", JSONString, offsetof(Discovery, token_endpoint)},
};

typedef struct Tokenresp Tokenresp;
struct Tokenresp
{
	char *access_token;
	char *id_token;
	char *token_type;
	double expires_in;
	char *refresh_token;
	char *scope;
};

static Elem trelems[] =
{
	{"access_token", JSONString, offsetof(Tokenresp, access_token)},
	{"id_token", JSONString, offsetof(Tokenresp, id_token)},
	{"token_type", JSONString, offsetof(Tokenresp, token_type)},
	{"expires_in", JSONNumber, offsetof(Tokenresp, expires_in)},
	{"refresh_token", JSONString, offsetof(Tokenresp, refresh_token)},
	{"scope", JSONString, offsetof(Tokenresp, scope)},
};


static char *typename[] =
{
	[JSONNull] "JSONNull",
	[JSONBool] "JSONBool",
	[JSONNumber] "JSONNumber",
	[JSONString] "JSONString",
	[JSONArray] "JSONArray",
	[JSONObject] "JSONObject",
};

void
jsondestroy(Elem *e, int n, void *out)
{
	int i;

	for(i = 0; i < n; i++){
		if(e[i].type == JSONString){
			free(*(char **)((char*)out + e[i].off));
			*(char**)((char*)out + e[i].off) = nil;
		}
	}
}

int
readjson(JSON *j, Elem* e, int n, void *out)
{
	int i;
	JSON *t;
	for(i = 0; i < n; i++){
		if((t = jsonbyname(j, e[i].name)) == nil){
			/* it's okay if a key is missing */
			continue;
		}
		if(e[i].type != t->t){
			werrstr("types for key %s do not match: need %s, got %s", e[i].name, typename[e[i].type], typename[t->t]);
			jsondestroy(e, n, out);
			return -1;
		}
		switch(e[i].type){
		default:
			werrstr("no way to read type %s", typename[e[i].type]);
			jsondestroy(e, n, out);
			return -1;
		case JSONNumber:
			*(double *)((char*)out + e[i].off) = t->n;
			break;
		case JSONString:
			if((*(char **)((char*)out + e[i].off) = strdup(t->s)) == nil){
				werrstr("strdup: %r");
				jsondestroy(e, n, out);
				return -1;
			}
			break;
		}
	}
	return 0;
}

int
discoveryget(char *issuer, Discovery *disc)
{
	JSON *jv;

	jv = jsonrpc(&https, issuer, "/.well-known/openid-configuration", nil);
	if(jv == nil){
		werrstr("jsonrpc: %r");
		return -1;
	}

	if(readjson(jv, discelems, nelem(discelems), disc) < 0){
		werrstr("readjson: %r");
		jsonfree(jv);
		return -1;
	}

	return 0;

}

char
randalnum(void)
{
		ulong x;
		char c;

		x = ntruerand(26 + 26 + 10);
		if(x < 26)
			return ('a' + i);
		x -= 26;
		if(x < 26)
			return ('A' + i);
		x -= 26;

		return ('0' + i);
}


int
authcodeflow(char *issuer, char *scope, char *client_id, char *client_secret)
{
	char verifier[Verifierlen];
	char hash[SHA2_256dlen];
	char challenge[2 * (sizeof hash)];
	char state[Statelen + 1];
	char *pos;
	char *s;
	Discovery disc;
	Tokenresp tr;
	Fmt fmt;
	int ofd;
	int wfd;
	int r;


	memset(disc, 0, sizeof disc);
	fmtstrinit(&fmt);
	/* generate code verifier */
	for(i = 0; i < Verifierlen; i++){
		verifier[i] = randalnum();
	}
	for(i = 0; i < Statelen; i++){
		state[i] = randalnum();
	}
	state[Statelen] = '\0';

	sha2_256(verifier, sizeof verifier, hash, nil);
	snprint(challenge, sizeof challenge, "%.*[", sizeof hash, hash);

	if((pos = strchr(challenge, '=')) != nil)
		*pos = '\0';
	while((pos = strchr(challenge, '+')) != nil)
		*pos = '-';
	while((pos = strchr(challenge, '/')) != nil)
		*pos = '_';

	/* parse discovery document */
	r = discoveryget(issuer, &disc);
	if(r < 0){
		werrstr("discoveryget: %r");
		return -1;
	}

	if(disc.authorization_endpoint == nil){
		werrstr("no authorization_endpoint");
		r = -1;
		goto out;
	}

	if(disc.token_endpoint == nil){
		werrstr("no token_endpoint");
		r = -1;
		goto out;
	}

	fmtprint(&fmt, "%s?", disc.authorization_endpoint);
	/* append client_id to url */
	fmtprint(&fmt, "%U=%U", "client_id", client_id);
	/* append redirect_uri to url */
	fmtprint(&fmt, "&%U=%U", "redirect_uri", "plumbtext");
	/* append response_type to url */
	fmtprint(&fmt, "&%U=%U", "response_type", "code");
	/* append scope to url */
	fmtprint(&fmt, "&%U=%U", "scope", scope);
	/* append code_challenge to url */
	fmtprint(&fmt, "&%U=%U", "code_challenge", challenge);
	/* append code_challenge_method to url */
	fmtprint(&fmt, "&%U=%U", "code_challenge_method", "S256");
	/* append state to url */
	fmtprint(&fmt, "&%U=%U", "state", state);


	if((s = fmtstrflush(&fmt)) == nil){
		werrstr("fmtstrflush: %r");
		r = -1;
		goto out;
	}


	/* plumb url to browser */
	if((ofd = plumbopen("web", OWRITE)) < 0){
		werrstr("plumbopen: %r");
		r = -1;
		goto out;
	}

	/* TODO */
	/* listen for response on plumb */
	/* verify state1 == state2 */
	/* exchange code with code_challenge for token */
	/* print tokens */
	/* done! */
}