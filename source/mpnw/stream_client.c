#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct StreamClient
{
	StreamClientReceive receiveFunction;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	struct SocketAddress* remoteAddress;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void streamClientReceiveHandler(
	void* argument)
{
	struct StreamClient* client =
		(struct StreamClient*)argument;
	struct SocketAddress* remoteAddress =
		client->remoteAddress;
	StreamClientReceive receiveFunction =
		client->receiveFunction;
	void* functionArgument =
		client->functionArgument;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	struct Socket* receiveSocket =
		client->receiveSocket;

	bool result = connectSocket(
		receiveSocket,
		remoteAddress);

	if (result == false)
		return;

	size_t byteCount;

	client->threadRunning = true;

	while (true)
	{
		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false || byteCount == 0)
			break;

		result = receiveFunction(
			client,
			receiveBuffer,
			byteCount,
			functionArgument);

		if (result == false)
			break;
	}

	client->threadRunning = false;
}

struct StreamClient* createStreamClient(
	const struct SocketAddress* _remoteAddress,
	StreamClientReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext)
{
	assert(_remoteAddress != NULL);
	assert(receiveFunction != NULL);
	assert(receiveBufferSize != 0);

	struct StreamClient* client = malloc(
		sizeof(struct StreamClient));

	if (client == NULL)
		return NULL;

	struct SocketAddress* remoteAddress =
		copySocketAddress(_remoteAddress);

	if (remoteAddress == NULL)
	{
		free(client);
		return NULL;
	}

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	uint8_t addressFamily = getSocketAddressFamily(
		_remoteAddress);
	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		sslContext);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	struct SocketAddress* localAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_PORT);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_PORT);
	}
	else
	{
		abort();
	}

	if (localAddress == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	bool result = bindSocket(
		receiveSocket,
		localAddress);

	destroySocketAddress(
		localAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	client->remoteAddress = remoteAddress;
	client->receiveFunction = receiveFunction;
	client->functionArgument = functionArgument;
	client->receiveBufferSize = receiveBufferSize;
	client->receiveBuffer = receiveBuffer;
	client->threadRunning = false;
	client->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		streamClientReceiveHandler,
		client);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}

void destroyStreamClient(
	struct StreamClient* client)
{
	if (client == NULL)
		return;

	destroySocket(client->receiveSocket);
	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	free(client->receiveBuffer);
	destroySocketAddress(client->remoteAddress);
	free(client);
}

bool isStreamClientRunning(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->threadRunning;
}

const struct Socket* getStreamClientSocket(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->receiveSocket;
}

bool streamClientSend(
	struct StreamClient* client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);
	assert(count != 0);

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
