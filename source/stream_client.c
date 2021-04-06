#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <time.h>
#include <assert.h>

struct StreamClient
{
	size_t receiveBufferSize;
	StreamClientReceive receiveFunction;
	void* handle;
	uint8_t* receiveBuffer;
	Socket* receiveSocket;
	Thread* receiveThread;
	volatile bool threadRunning;
};

static void streamClientReceiveHandler(
	void* argument)
{
	StreamClient* client =
		(StreamClient*)argument;
	StreamClientReceive receiveFunction =
		client->receiveFunction;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	Socket* receiveSocket =
		client->receiveSocket;

	bool result;
	size_t byteCount;

	while (client->threadRunning == true)
	{
		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false)
		{
			sleepThread(0.001);
			continue;
		}

		result = receiveFunction(
			client,
			receiveBuffer,
			byteCount);

		if (result == false)
			break;
	}

	client->threadRunning = false;
}

StreamClient* createStreamClient(
	uint8_t addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* handle,
	SslContext* sslContext)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(receiveBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(isNetworkInitialized() == true);

	StreamClient* client = malloc(
		sizeof(StreamClient));

	if (client == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(client);
		return NULL;
	}

	SocketAddress* localAddress;

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
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	if (localAddress == NULL)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		false,
		false,
		sslContext);

	destroySocketAddress(localAddress);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveBufferSize = receiveBufferSize;
	client->receiveFunction = receiveFunction;
	client->handle = handle;
	client->receiveBuffer = receiveBuffer;
	client->receiveSocket = receiveSocket;
	client->threadRunning = true;

	Thread* receiveThread = createThread(
		streamClientReceiveHandler,
		client);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}

void destroyStreamClient(StreamClient* client)
{
	assert(isNetworkInitialized() == true);

	if (client == NULL)
		return;

	client->threadRunning = false;

	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	shutdownSocket(
		client->receiveSocket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(client->receiveSocket);

	free(client->receiveBuffer);
	free(client);
}

size_t getStreamClientReceiveBufferSize(
	const StreamClient* client)
{
	assert(client != NULL);
	return client->receiveBufferSize;
}

StreamClientReceive getStreamClientReceiveFunction(
	const StreamClient* client)
{
	assert(client != NULL);
	return client->receiveFunction;
}

void* getStreamClientHandle(
	const StreamClient* client)
{
	assert(client != NULL);
	return client->handle;
}

Socket* getStreamClientSocket(
	const StreamClient* client)
{
	assert(client != NULL);
	return client->receiveSocket;
}

bool isStreamClientRunning(
	const StreamClient* client)
{
	assert(client != NULL);
	return client->threadRunning;
}

bool connectStreamClient(
	StreamClient* streamClient,
	const SocketAddress* address,
	double timeoutTime)
{
	assert(streamClient != NULL);
	assert(address != NULL);

	Socket* socket = streamClient->receiveSocket;
	double timeout = getCurrentClock() + timeoutTime;

	while (getCurrentClock() < timeout)
	{
		bool result = connectSocket(
			socket,
			address);

		if (result == true)
			goto CONNECT_SSL;
	}

	return false;

CONNECT_SSL:

	if (getSocketSslContext(socket) == NULL)
		return true;

	while (getCurrentClock() < timeout)
	{
		bool result = connectSslSocket(
			socket);

		if (result == true)
			return true;
	}

	return false;
}

bool streamClientSend(
	StreamClient* client,
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
