#pragma once
#include "mpnw/http.h"
#include "mpnw/stream_client.h"

/* HTTP client instance handle */
struct HttpClient;

/* HTTP client response receive function */
typedef bool(*HttpClientReceive)(
	struct HttpClient* client,
	const struct HttpResponse* response,
	void* argument);

/*
 * Creates a new HTTP client.
 * Returns HTTP client on success, otherwise null.
 *
 * addressFamily - local HTTP socket address family.
 * remoteAddress - pointer to the valid server address.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the server function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct HttpClient* createHttpClient(
	const struct SocketAddress* remoteAddress,
	HttpClientReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext);

/*
 * Destroys specified HTTP client.
 * client - pointer to the HTTP client or NULL.
 */
void destroyHttpClient(
	struct HttpClient* client);

/*
 * Returns HTTP client stream.
 * client - pointer to the valid HTTP client.
 */
const struct StreamClient* getHttpClientStream(
	const struct HttpClient* client);

/*
 * Sends request to the HTTP server.
 * Returns true on success.
 *
 * client - pointer to the valid HTTP client.
 * type - HTTP request type.
 * uri - pointer to the valid HTTP URI.
 * version - HTTP protocol version.
 */
bool httpClientSend(
	struct HttpClient* client,
	uint8_t type,
	const char* uri,
	uint8_t version);
