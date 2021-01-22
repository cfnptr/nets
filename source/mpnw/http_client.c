#include "mpnw/http_client.h"
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

	struct HttpResponse* response = deserializeHttpResponse(
		(const char*)buffer,
		count);

	if (response == NULL)
		return false;

	bool result = httpClient->receiveFunction(
		httpClient,
		response,
		httpClient->functionArgument);

	destroyHttpResponse(response);
	return result;
}

struct HttpClient* createHttpClient(
	const struct SocketAddress* remoteAddress,
	HttpClientReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext)
{
	assert(remoteAddress != NULL);
	assert(receiveFunction != NULL);

	struct HttpClient* client = malloc(
		sizeof(struct HttpClient));

	if (client == NULL)
		return NULL;

	struct StreamClient* handle = createStreamClient(
		remoteAddress,
		httpClientReceive,
		client,
		receiveBufferSize,
		sslContext);

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

const struct StreamClient* getHttpClientStream(
	const struct HttpClient* client)
{
	assert(client != NULL);
	return client->handle;
}

bool httpClientSend(
	struct HttpClient* client,
	uint8_t type,
	const char* uri,
	uint8_t version)
{
	assert(client != NULL);
	assert(uri != NULL);

	size_t size;

	char* data = serializeHttpRequest(
		type,
		uri,
		version,
		&size);

	if (data == NULL)
		return false;

	bool result = streamClientSend(
		client->handle,
		data,
		size);

	free(data);
	return result;
}
