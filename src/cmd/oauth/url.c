#include "a.h"

/* 9front /sys/src/cmd/webfs/url.c */

static char reserved[] = "%:/?#[]@!$&'()*+,;=";

static int
dhex(char c)
{
	if('0' <= c && c <= '9')
		return c-'0';
	if('a' <= c && c <= 'f')
		return c-'a'+10;
	if('A' <= c && c <= 'F')
		return c-'A'+10;
	return 0;
}

static char*
unescape(char *s, char *spec)
{
	char *r, *w;
	uchar x;

	if(s == nil)
		return s;
	for(r=w=s; x = *r; r++){
		if(x == '%' && isxdigit(r[1]) && isxdigit(r[2])){
			x = (dhex(r[1])<<4)|dhex(r[2]);
			if(spec && strchr(spec, x)){
				*w++ = '%';
				*w++ = toupper(r[1]);
				*w++ = toupper(r[2]);
			}
			else
				*w++ = x;
			r += 2;
			continue;
		}
		*w++ = x;
	}
	*w = 0;
	return s;
}


char*
Upath(Url *u)
{
	if(u){
		if(u->path)
			return u->path;
		if(u->user || u->host)
			return "/";
	}
	return nil;
}

static char*
remdot(char *s)
{
	char *b, *d, *p;
	int dir, n;

	dir = 1;
	b = d = s;
	if(*s == '/')
		s++;
	for(; s; s = p){
		if(p = strchr(s, '/'))
			*p++ = 0;
		if(*s == '.' && ((s[1] == 0) || (s[1] == '.' && s[2] == 0))){
			if(s[1] == '.')
				while(d > b)
					if(*--d == '/')
						break;
			dir = 1;
			continue;
		} else
			dir = (p != nil);
		if((n = strlen(s)) > 0)
			memmove(d+1, s, n);
		*d++ = '/';
		d += n;
	}
	if(dir)
		*d++ = '/';
	*d = 0;
	return b;
}

static char*
abspath(char *s, char *b)
{
	char *x, *a;

	if(b && *b){
		if(s == nil || *s == 0)
			return estrdup(b);
		if(*s != '/' && (x = strrchr(b, '/'))){
			a = emalloc((x - b) + strlen(s) + 4);
			sprint(a, "%.*s/%s", utfnlen(b, x - b), b, s);
			return remdot(a);
		}
	}
	if(s && *s){
		if(*s != '/')
			return estrdup(s);
		a = emalloc(strlen(s) + 4);
		sprint(a, "%s", s);
		return remdot(a);
	}
	return nil;
}

static void
pstrdup(char **p)
{
	if(p == nil || *p == nil)
		return;
	if(**p == 0){
		*p = nil;
		return;
	}
	*p = estrdup(*p);
}

static char*
mklowcase(char *s)
{
	char *cp;
	Rune r;

	if(s == nil)
		return s;
	cp = s;
	while(*cp != 0){
		chartorune(&r, cp);
		r = tolowerrune(r);
		cp += runetochar(cp, &r);
	}
	return s;
}

Url*
url(char *s)
{
	char *t, *p, *x, *y;
	Url *u;

	if(s == nil)
		s = "";
	t = nil;
	s = p = estrdup(s);
	u = emalloc(sizeof(*u));
	for(; *p; p++){
		if(*p == ':'){
			if(p == s)
				break;
			*p++ = 0;
			u->scheme = s;
			goto Abs;
		}
		if(!isalpha(*p))
			if((p == s) || ((!isdigit(*p) && strchr("+-.", *p) == nil)))
				break;
	}
	p = s;
Abs:
	if(x = strchr(p, '#')){
		*x = 0;
		u->fragment = x+1;
	}
	if(x = strchr(p, '?')){
		*x = 0;
		u->query = x+1;
	}
	if(p[0] == '/' && p[1] == '/'){
		p += 2;
		if(x = strchr(p, '/')){
			u->path = t = abspath(x, nil);
			*x = 0;
		}
		if(x = strchr(p, '@')){
			*x = 0;
			if(y = strchr(p, ':')){
				*y = 0;
				u->pass = y+1;
			}
			u->user = p;
			p = x+1;
		}
		if((x = strrchr(p, ']')) == nil)
			x = p;
		if(x = strrchr(x, ':')){
			*x = 0;
			u->port = x+1;
		}
		if(x = strchr(p, '[')){
			p = x+1;
			if(y = strchr(p, ']'))
				*y = 0;
		}
		u->host = p;
	} else {
		u->path = t = abspath(p, nil);
	}
Out:
	pstrdup(&u->scheme);
	pstrdup(&u->user);
	pstrdup(&u->pass);
	pstrdup(&u->host);
	pstrdup(&u->port);
	pstrdup(&u->path);
	pstrdup(&u->query);
	pstrdup(&u->fragment);
	free(s);
	free(t);

	/* the + character encodes space only in query part */
	if(s = u->query)
		while(s = strchr(s, '+'))
			*s++ = ' ';

	if(s = u->host){
		t = emalloc(Domlen);
		if(idn2utf(s, t, Domlen) >= 0){
			u->host = estrdup(t);
			free(s);
		}
		free(t);
	}

	unescape(u->user, nil);
	unescape(u->pass, nil);
	unescape(u->path, reserved);
	unescape(u->query, reserved);
	unescape(u->fragment, reserved);
	mklowcase(u->scheme);
	mklowcase(u->host);
	mklowcase(u->port);

	return u;
}

Url*
saneurl(Url *u)
{
	if(u == nil || u->scheme == nil || u->host == nil || Upath(u) == nil){
		freeurl(u);
		return nil;
	}
	if(u->port){
		/* remove default ports */
		switch(atoi(u->port)){
		case 21:	if(!strcmp(u->scheme, "ftp"))	goto Defport; break;
		case 70:	if(!strcmp(u->scheme, "gopher"))goto Defport; break;
		case 80:	if(!strcmp(u->scheme, "http"))	goto Defport; break;
		case 443:	if(!strcmp(u->scheme, "https"))	goto Defport; break;
		default:	if(!strcmp(u->scheme, u->port))	goto Defport; break;
		Defport:
			free(u->port);
			u->port = nil;
		}
	}
	return u;
}
