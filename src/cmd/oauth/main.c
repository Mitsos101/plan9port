#include "a.h"

void
usage(void)
{
	fprint(2, "usage: oauth issuer scope client_id [client_secret]\n");
	threadexitsall("usage");
}

void
threadmain(int argc, char **argv)
{
	char *issuer, *scope, *client_id, *client_secret;

	ARGBEGIN{
	default:
		usage();
	}ARGEND

	if(argc != 3 && argc != 4)
		usage();

	quotefmtinstall();
	fmtinstall('[', encodefmt);  // base-64
	fmtinstall('J', JSONfmt);
	fmtinstall('U', urlencodefmt);

	issuer = argv[0];
	scope = argv[1];
	client_id = argv[2];
	if(argc == 4)
		client_secret = argv[3];
	else
		client_secret = nil;

	if(authcodeflow(issuer, scope, client_id, client_secret) < 0){
		sysfatal("authcodeflow: %r");
	}

	threadexitsall(nil);
}
