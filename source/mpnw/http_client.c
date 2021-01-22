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
	void* functionArgument,
	size_t receiveBufferSize)
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
		receiveBufferSize);

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
	struct HttpRequest request)
{
	assert(client != NULL);

	char* data;
	size_t size;

	bool result = serializeHttpRequest(
		request,
		&data,
		&size);

	if (result == false)
		return false;

	result = streamClientSend(
		client->handle,
		data,
		size);

	free(data);
	return result;
}
