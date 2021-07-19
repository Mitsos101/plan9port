#include "a.h"

// JSON RPC over HTTP

static char*
makehttprequest(char *host, char *path, char *postdata)
{
	Fmt fmt;

	fmtstrinit(&fmt);
	if(postdata){
		fmtprint(&fmt, "POST %s HTTP/1.0\r\n", path);
		fmtprint(&fmt, "Host: %s\r\n", host);
		fmtprint(&fmt, "User-Agent: " USER_AGENT "\r\n");
		fmtprint(&fmt, "Content-Type: application/x-www-form-urlencoded\r\n");
		fmtprint(&fmt, "Content-Length: %d\r\n", strlen(postdata));
		fmtprint(&fmt, "\r\n");
		fmtprint(&fmt, "%s", postdata);
	} else{
		fmtprint(&fmt, "GET %s HTTP/1.0\r\n", path);
		fmtprint(&fmt, "Host: %s\r\n", host);
		fmtprint(&fmt, "User-Agent: " USER_AGENT "\r\n");
	}
	return fmtstrflush(&fmt);
}

static char*
makerequest(char *name1, va_list arg)
{
	char *p, *key, *val;
	Fmt fmt;
	int first;

	fmtstrinit(&fmt);
	first = 1;
	p = name1;
	while(p != nil){
		key = p;
		val = va_arg(arg, char*);
		if(val == nil){
			werrstr("jsonrpc: nil value");
			free(fmtstrflush(&fmt));
			return nil;
		}
		fmtprint(&fmt, first + "&%U=%U", key, val);
		first = 0;
		p = va_arg(arg, char*);
	}
	return fmtstrflush(&fmt);
}

static char*
dojsonhttp(Protocol *proto, char *host, char *request)
{
	char *data;
	HTTPHeader hdr;

	data = httpreq(proto, host, request, &hdr);
	if(data == nil){
		werrstr("httpreq: %r");
		return nil;
	}
	if(strcmp(hdr.contenttype, "application/json") != 0){
		werrstr("bad content type: %s", hdr.contenttype);
		return nil;
	}
	if(hdr.contentlength == 0){
		werrstr("no content");
		return nil;
	}
	return data;
}

Json*
jsonrpc(Protocol *proto, char *host, char *path, char *request)
{
	char *httpreq, *request, *reply;
	Json *jv, *jerror;

	httpreq = makehttprequest(host, path, request);
	free(request);

	if((reply = dojsonhttp(proto, host, httpreq)) == nil){
		free(httpreq);
		return nil;
	}
	free(httpreq);

	jv = parsejson(reply);
	free(reply);
	if(jv == nil){
		werrstr("error parsing JSON reply: %r");
		return nil;
	}

	if((jerror = jlookup(jv, "error")) == nil){
		return jv;
	}

	werrstr("%J", jerror);
	jclose(jv);
	return nil;
}

Json*
ncpost(char *host, char *path, char *name1, ...)
{
	Json *jv;
	va_list arg;

	va_start(arg, name1);
	jv = jsonrpc(&https, host, path, makerequest(name1, arg));
	va_end(arg);
	return jv;
}

Json*
ncget(char *host, char *path)
{
	Json *jv;

	jv = jsonrpc(&https, host, path, nil);
	return jv;
}

Json*
urlpost(char *s, char *name1, ...)
{
	Json *jv;
	va_list arg;
	Url *u;

	if((u = saneurl(url(s))) == nil){
		werrstr("url parsing error");
		return nil;
	}

	va_start(arg, name1);
	jv = jsonrpc(&https, u->host, Upath(u), makerequest(name1, arg));
	va_end(arg);
	freeurl(u);
	return jv;
}

Json*
urlget(char *s)
{
	Json *jv;
	Url *u;

	if((u = saneurl(url(s))) == nil){
		werrstr("url parsing error");
		return nil;
	}

	jv = jsonrpc(&https, u->host, Upath(u), nil);
	freeurl(u);
	return jv;
}


