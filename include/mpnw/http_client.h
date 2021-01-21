#pragma once
#include "mpnw/socket.h"

/* HTTP client instance handle */
struct HttpClient;

/* HTTP client response receive function */
typedef bool(*HttpClientReceive)(
	struct HttpClient* client,
	const char* response,
	size_t count,
	void* argument);

/*
 * Creates a new HTTP client.
 * Returns HTTP client on success, otherwise null.
 *
 * addressFamily - local stream socket address family.
 * sslContext - pointer to the SSL context or NULL.
 * remoteAddress - pointer to the valid server address.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the server function argument.
 */
struct HttpClient* createHttpClient(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const struct SocketAddress* remoteAddress,
	HttpClientReceive receiveFunction,
	void* functionArgument);

/*
 * Destroys specified HTTP client.
 * client - pointer to the HTTP client or NULL.
 */
void destroyHttpClient(
	struct HttpClient* client);

/*
 * Returns current HTTP client running state.
 * client - pointer to the valid HTTP client.
 */
bool getHttpClientRunning(
	const struct HttpClient* client);

/*
 * Sends request to the HTTP server.
 * Returns true on success.
 *
 * TODO: description
 */
bool httpClientSend(
	struct HttpClient* client,
	const char* request,
	size_t count);
