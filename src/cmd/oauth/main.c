#include "a.h"

void
usage(void)
{
	fprint(2, "usage: oauth [-dr] issuer scope client_id client_secret [refresh_token]\n");
	threadexitsall("usage");
}

void
threadmain(int argc, char **argv)
{
	int usedev;
	int useref;
	char *issuer, *scope, *client_id, *client_secret, *refresh_token;

	usedev = 0;
	useref = 0;
	ARGBEGIN{
	default:
		usage();
	case 'd':
		usedev++;
		break;
	case 'r':
		useref++;
		break;
	}ARGEND

	if(argc != 3 && argc != 4 && argc != 5)
		usage();

	quotefmtinstall();
	fmtinstall('[', encodefmt);  // base-64
	fmtinstall('J', JSONfmt);
	fmtinstall('U', urlencodefmt);

	issuer = argv[0];
	scope = argv[1];
	client_id = argv[2];
	client_secret = argv[3];
	if(useref){
		if(argc != 5){
			sysfatal("missing refresh token");
		}
		refresh_token = argv[4];
		if(refreshflow(issuer, scope, client_id, client_secret, refresh_token) < 0){
			sysfatal("refreshflow: %r");
		}
	} else if(usedev){
		if(deviceflow(issuer, scope, client_id, client_secret) < 0){
			sysfatal("deviceflow: %r");
		}
	} else{
		if(authcodeflow(issuer, scope, client_id, client_secret) < 0){
			sysfatal("authcodeflow: %r");
		}
	}

	threadexitsall(nil);
}
