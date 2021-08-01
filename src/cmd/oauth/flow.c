#include "a.h"

enum
{
	Verifierlen = 100,
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
	char *device_authorization_endpoint;
};

static Elem discelems[] =
{
	{"authorization_endpoint", JSONString, offsetof(Discovery, authorization_endpoint)},
	{"token_endpoint", JSONString, offsetof(Discovery, token_endpoint)},
	{"device_authorization_endpoint", JSONString, offsetof(Discovery, device_authorization_endpoint)},
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
	/* {"id_token", JSONString, offsetof(Tokenresp, id_token)}, we can't use this */
	{"token_type", JSONString, offsetof(Tokenresp, token_type)},
	{"expires_in", JSONNumber, offsetof(Tokenresp, expires_in)},
	{"refresh_token", JSONString, offsetof(Tokenresp, refresh_token)},
	{"scope", JSONString, offsetof(Tokenresp, scope)},
};

typedef struct Deviceresp Deviceresp;
struct Deviceresp
{
	char *device_code;
	char *user_code;
	char *verification_uri;
	double expires_in;
	double interval;
};

static Elem drelems[] =
{
	{"device_code", JSONString, offsetof(Deviceresp, device_code)},
	{"user_code", JSONString, offsetof(Deviceresp, user_code)},
	{"verification_url", JSONString, offsetof(Deviceresp, verification_uri)}, /* google misspells this field */
	{"verification_uri", JSONString, offsetof(Deviceresp, verification_uri)},
	{"expires_in", JSONNumber, offsetof(Deviceresp, expires_in)},
	{"interval", JSONNumber, offsetof(Deviceresp, interval)},
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
	/* TODO: support multiple issuers per host and validate the issuer */
	JSON *jv;

	jv = jsonrpc(&https, issuer, "/.well-known/openid-configuration", nil, nil, nil);
	if(jv == nil){
		werrstr("jsonrpc: %r");
		return -1;
	}

	if(readjson(jv, discelems, nelem(discelems), disc) < 0){
		werrstr("readjson: %r");
		jsonfree(jv);
		return -1;
	}

	if(disc.authorization_endpoint == nil){
		werrstr("no authorization_endpoint");
		return -1;
	}

	if(disc.token_endpoint == nil){
		werrstr("no token_endpoint");
		return -1;
	}

	return 0;

}

int
printkey(char *issuer, char *client_id, char *client_secret, char *scope, JSON *j)
{
	Tokenresp tr;
	long exptime;

	memset(&tr, 0, sizeof tr);
	if(readjson(j, trelems, nelem(trelems), &tr) < 0){
		werrstr("readjson: %r");
		return -1;
	}
	if(tr.token_type == nil || tr.access_token == nil){
		werrstr("missing key");
		jsondestroy(trelems, nelem(trelems), &tr);
		return -1;
	}


	if(tr.expires_in == 0)
		tr.expires_in = (long)1800; /* picked at random */

	exptime = time(0) + (long)tr.expires_in;

	/* do not modify scope if the server modifies it, as we can't match on the scope if we change it */
	print("key proto=oauth issuer=%q client_id=%q token_type=%q exptime=%ld scope=%q", issuer, client_id, tr.token_type, exptime, scope);
	print(" !client_secret=%q !access_token=%q", client_secret, tr.access_token);
	if(tr.refresh_token != nil)
		print(" !refresh_token=%q", tr.refresh_token);
	print("\n");


	jsondestroy(trelems, nelem(trelems), &tr);
	return 0;
}


int
deviceflow(char *issuer, char *scope, char *client_id, char *client_secret)
{
	char errbuf[ERRMAX];
	Discovery disc;
	Deviceresp dr;
	JSON *j;
	int r;

	memset(&disc, 0, sizeof disc);
	memset(&dr, 0, sizeof dr);
	memset(&tr, 0, sizeof tr);

	r = discoveryget(issuer, &disc);
	if(r < 0){
		werrstr("flowinit: %r");
		goto out;
	}

	dr.interval = 5;
	j = urlpost(disc.device_authorization_endpoint, nil, nil, "scope", scope, "client_id", client_id, nil);
	if(j == nil){
		r = -1;
		werrstr("urlpost device_authorization_endpoint: %r");
		goto out;
	}
	r = readjson(j, drelems, nelem(drelems), &dr);
	if(r < 0){
		werrstr("readjson: %r");
		goto out;
	}
	if(dr.verification_uri == nil || dr.user_code == nil || dr.device_code == nil){
		r = -1;
		werrstr("missing key");
		goto out;
	}
	fprint(2, "verification_uri=%q user_code=%q", dr.verification_uri, dr.user_code);
	for(;;sleep((long)dr.interval * 1000L)){
		j = urlpost(disc.token_endpoint, client_id, client_secret,
		            "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
		            "device_code", dr.device_code,
		            nil);
		if(j == nil){
			jsondestroy(trelems, nelem(trelems), &tr);
			memset(&tr, 0, sizeof tr);
			/* check for special errors, don't give up yet */
			rerrstr(errbuf, sizeof errbuf);
			if(strstr(errbuf, "authorization_pending") != nil){
				continue;
			}
			if(strstr(errbuf, "slow_down") != nil){
				dr.interval += 5;
				continue;
			}
			r = -1;
			werrstr("urlpost token_endpoint: %r");
			goto out;
		}
		break;
	}
	r = printkey(issuer, client_id, client_secret, scope, j);
	if(r < 0){
		werrstr("printkey: %r");
		goto out;
	}
	r = 0;
	out:
	jsondestroy(drelems, nelem(drelems), &dr);
	jsondestroy(discelems, nelem(discelems), &disc);
	return r;
}

int
refreshflow(char *issuer, char *scope, char *client_id, char *client_secret, char *refresh_token)
{
	Discovery disc;
	JSON *j;
	int r;

	r = discoveryget(issuer, &disc);
	if(r < 0){
		werrstr("discoveryget: %r");
		goto out;
	}

	j = urlpost(disc.token_endpoint, client_id, client_secret,
	            "grant_type", "refresh_token",
	            "refresh_token", refresh_token,
	            nil);

	if(j == nil){
		r = -1;
		werrstr("urlpost: %r");
		goto out;
	}

	r = printkey(issuer, client_id, client_secret, scope, j);
	if(r < 0){
		werrstr("printkey: %r");
		goto out;
	}

	r = 0;
	out:
	jsondestroy(discelems, nelem(discelems), &disc);
}

int
fillrandom(char *s, int n)
{
	int len;
	char *pos;
	char buf[256];
	char buf2[256];

	if(n % 4 != 0){
		werrstr("length must be divisible by 4");
		return -1;
	}
	len = (n / 4) * 3;

	genrandom(buf, len);
	snprint(buf2, sizeof buf2, "%.*[", len, buf);

	if((pos = strchr(buf2, '=')) != nil)
		*pos = '\0';
	while((pos = strchr(buf2, '+')) != nil)
		*pos = '-';
	while((pos = strchr(buf2, '/')) != nil)
		*pos = '_';

	strcpy(s, buf2);

	return 0;

}

int
authcodeflow(char *issuer, char *scope, char *client_id, char *client_secret)
{
	char verifier[Verifierlen + 1];
	char hash[SHA2_256dlen];
	char challenge[2 * (sizeof hash)];
	char state[Statelen + 1];
	char *pos;
	char *s;
	char *state2;
	char *code;
	Discovery disc;
	JSON *j;
	Plumbmsg pm;
	Plumbmsg* pp;
	Fmt fmt;
	int wfd;
	int ofd;
	int r;
	int i;


	memset(&disc, 0, sizeof disc);
	fmtstrinit(&fmt);
	/* generate code verifier and state */
	if(fillrandom(verifier, Verifierlen) < 0 || fillrandom(state, Statelen) < 0){
		r = -1;
		werrstr("fillrandom: %r");
	}
	verifier[Verifierlen] = '\0';
	state[Statelen] = '\0';

	sha2_256(verifier, Verifierlen, hash, nil);
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

	fmtprint(&fmt, "%s?", disc.authorization_endpoint);
	/* append client_id to url */
	fmtprint(&fmt, "%U=%U", "client_id", client_id);
	/* append redirect_uri to url */
	fmtprint(&fmt, "&%U=%U", "redirect_uri", "http://127.0.0.1:4812"); /* it is difficult to register a scheme for the plumber */
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
	if((wfd = plumbopen("send", OWRITE)) < 0){
		werrstr("plumbopen: %r");
		r = -1;
		goto out;
	}

	pm = (Plumbmsg){"oauth", "web", nil, "text", nil, strlen(s), s};

	if(plumbsend(wfd, &pm) < 0){
		werrstr("plumbsend: %r");
		r = -1;
		goto out;
	}

	/* how do you close wfd? */

	/* listen for response on plumb */
	if((ofd = plumbopen("oauth", OREAD)) < 0){
		werrstr("plumbopen: %r");
		r = -1;
		goto out;
	}

	while((pp = plumbrecv(ofd)) != nil){
		if((state2 = plumblookup(pp->attr, "state")) == nil
		|| (code = plumblookup(pp->attr, "code")) == nil
		|| strcmp(state, state2) != 0){
			plumbfree(pp);
			continue;
		}
		j = urlpost(disc.token_endpoint, client_id, client_secret,
					"code", code,
					"code_verifier", verifier,
					"redirect_uri", "http://127.0.0.1:4812",
					"grant_type", "authorization_code",
					nil);

		if(j == nil){
			werrstr("urlpost: %r");
			r = -1;
			goto out;
		}

		if(printkey(issuer, client_id, client_secret, scope, j) < 0){
			werrstr("printkey: %r");
			jsonfree(j);
			plumbfree(pp);
			r = -1;
			goto out;
		}
		jsonfree(j);
		plumbfree(pp);
		break;
	}

	if(pp == nil){
		werrstr("plumbrecv: %r");
		r = -1;
		goto out;
	}


	r = 0;
	out:
	jsondestroy(discelems, nelem(discelems), &disc);
	return r;
}
