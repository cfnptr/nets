#include "mpnw/http_server.h"

struct HttpServer
{
	HttpSessionReceive receiveFunction;
	void* functionArgument;
	struct StreamServer* handle;
};

bool httpSessionReceive(
	struct StreamSession* session,
	const uint8_t* buffer,
	size_t count,
	void* argument)
{
	struct HttpServer* httpServer =
		(struct HttpServer*)argument;

	struct HttpRequest* request = deserializeHttpRequest(
		(const char*)buffer,
		count);

	if (request == NULL)
		return false;

	bool result = httpServer->receiveFunction(
		session,
		request,
		httpServer->functionArgument);

	destroyHttpRequest(request);
	return result;
}

struct HttpServer* createHttpServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	HttpSessionReceive receiveFunction,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext)
{
	assert(port != NULL);
	assert(receiveFunction != NULL);
	assert(sessionBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(receiveTimeoutTime != 0);
	assert(receiveBufferSize != 0);

	struct HttpServer* server = malloc(
		sizeof(struct HttpServer));

	if (server == NULL)
		return NULL;

	struct StreamServer* handle = createStreamServer(
		addressFamily,
		port,
		sessionBufferSize,
		httpSessionReceive,
		receiveTimeoutTime,
		server,
		receiveBufferSize,
		sslContext);

	if (handle == NULL)
	{
		free(server);
		return NULL;
	}

	server->receiveFunction = receiveFunction;
	server->functionArgument = functionArgument;
	server->handle = handle;
	return server;
}

void destroyHttpServer(
	struct HttpServer* server)
{
	if (server == NULL)
		return;

	destroyStreamServer(
		server->handle);
	free(server);
}

const struct StreamServer* getHttpClientStream(
	const struct HttpServer* server)
{
	assert(server != NULL);
	return server->handle;
}

bool httpSessionSend(
	struct StreamSession* session,
	uint8_t version,
	uint16_t status,
	const char* body)
{
	assert(session != NULL);
	assert(body != NULL);

	size_t size;

	// TODO:
	char* data = serializeHttpResponse(
		version,
		status,
		0,
		body,
		0,
		&size);

	if (data == NULL)
		return false;

	bool result = streamSessionSend(
		session,
		data,
		size);

	free(data);
	return result;
}
