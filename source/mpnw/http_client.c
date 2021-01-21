#include "mpnw/http_client.h"
#include "mpnw/stream_client.h"

#include <assert.h>

struct HttpClient
{
	HttpClientReceive receiveFunction;
	void* functionArgument;
	struct StreamClient* handle;
};

bool httpClientReceive(
	struct StreamClient* client,
	const uint8_t* buffer,
	size_t count,
	void* argument)
{
	struct HttpClient* httpClient =
		(struct HttpClient*)argument;

	// TODO: parse http response

	return httpClient->receiveFunction(
		httpClient,
		(const char*)buffer,
		count,
		httpClient->functionArgument);
}

struct HttpClient* createHttpClient(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const struct SocketAddress* remoteAddress,
	HttpClientReceive receiveFunction,
	void* functionArgument)
{
	assert(remoteAddress != NULL);
	assert(receiveFunction != NULL);

	struct HttpClient* client = malloc(
		sizeof(struct HttpClient));

	if (client == NULL)
		return NULL;

	struct StreamClient* handle = createStreamClient(
		addressFamily,
		sslContext,
		remoteAddress,
		httpClientReceive,
		client,
		65536);

	// TODO: select best receive buffer size

	if (handle == NULL)
	{
		free(client);
		return NULL;
	}

	client->receiveFunction = receiveFunction;
	client->functionArgument = functionArgument;
	client->handle = handle;
	return client;
}

void destroyHttpClient(
	struct HttpClient* client)
{
	if (client == NULL)
		return;

	destroyStreamClient(
		client->handle);
	free(client);
}

bool getHttpClientRunning(
	const struct HttpClient* client)
{
	assert(client != NULL);

	return getStreamClientRunning(
		client->handle);
}

bool httpClientSend(
	struct HttpClient* client,
	const char* request,
	size_t count)
{
	assert(client != NULL);
	assert(request != NULL);
	assert(count != 0);

	// TODO: parse response

	return streamClientSend(
		client->handle,
		request,
		count);
}
