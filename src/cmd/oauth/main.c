#include "a.h"

void
usage(void)
{
	fprint(2, "usage: refreshflow issuer scope client_id\n");
	exits("usage");
}

void
main(int argc, char **argv)
{
	char *issuer, *scope, *client_id;

	ARGBEGIN{
	default:
		usage();
	}ARGEND

	if(argc != 3)
		usage();

	quotefmtinstall();
	fmtinstall('J', jsonfmt);
	fmtinstall('U', urlencodefmt);

	issuer = argv[0];
	scope = argv[1];
	client_id = argv[2];

	if(authcodeflow(issuer, scope, client_id) < 0){
		sysfatal("authcodeflow: %r");
	}

	exits(nil);
}
