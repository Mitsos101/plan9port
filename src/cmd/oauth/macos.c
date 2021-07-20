#include <CommonCrypto/CommonDigest.h>
#include <Network/Network.h>
#include "a.h"

void* sha2_256(uchar *data, ulong len, uchar* buf, void* v)
{
	CC_SHA256(data, len, buf);
	return v;
}

struct Pfd
{
	nw_connection_t conn;
};


static Pfd*
macosconnect(char *host)
{
	nw_endpoint_t endpoint;
	nw_parameters_t parameters;
	nw_parameters_configure_protocol_block_t configure_tls;
	nw_parameters_configure_protocol_block_t configure_tcp;
	nw_connection_t connection;
	Pfd *pfd;

	endpoint = nw_endpoint_create_host(host, "https");

	configure_tls = NW_PARAMETERS_DEFAULT_CONFIGURATION;
	configure_tcp = NW_PARAMETERS_DEFAULT_CONFIGURATION;
	parameters = nw_parameters_create_secure_tcp(configure_tls, configure_tcp);

	connection = nw_connection_create(endpoint, parameters);
	nw_release(endpoint);
	nw_release(parameters);

	nw_connection_set_queue(connection, dispatch_get_main_queue());
	nw_connection_set_state_changed_handler(connection, NULL);
	nw_connection_start(connection);

	pfd = emalloc(sizeof(*pfd));
	pfd->conn = connection;
	return pfd;
}

static int
macoswrite(Pfd *pfd, void *v, int n)
{
	dispatch_data_t data;
	dispatch_group_t grp;
	__block int w;

	data = dispatch_data_create(v, (size_t)n, dispatch_get_main_queue(), DISPATCH_DATA_DESTRUCTOR_DEFAULT);
	/* it seems okay to use a dispatch group for a single task */
	grp = dispatch_group_create();
	dispatch_group_enter(grp);
	w = n;
	/* is_complete is true because we only call macoswrite once */
	nw_connection_send(pfd->conn, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
					if (error != NULL) {
						errno = nw_error_get_error_code(error);
						w = -1;
					}
					dispatch_group_leave(grp);
				});
	dispatch_release(data);
	dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
	dispatch_release(grp);
	return w;
}

static int
macosread(Pfd *pfd, void *v, int n)
{
	dispatch_group_t grp;
	__block int r;

	/* it seems okay to use a dispatch group for a single task */
	grp = dispatch_group_create();
	dispatch_group_enter(grp);
	r = 0;
	nw_connection_receive(pfd->conn, (uint32_t)n, (uint32_t)n, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t _Nullable receive_error) {
				if(receive_error != NULL) {
					errno = nw_error_get_error_code(receive_error);
					r = -1;
				} else {
					dispatch_data_apply(content, ^(__unused dispatch_data_t region, __unused size_t offset, const void *buf, size_t size) {
							memcpy(v, buf, size);
							r += size;
							return (bool)true;
						});
				}
				dispatch_group_leave(grp);
			});
	dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
	dispatch_release(grp);
	return r;
}

static void
macosclose(Pfd *pfd)
{
	if(pfd == nil)
		return;
	nw_release(pfd->conn);
	free(pfd);
}

Protocol https =
{
	macosconnect,
	macosread,
	macoswrite,
	macosclose
};

