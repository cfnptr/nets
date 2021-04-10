#include "mpnw/datagram_client.h"

#include "mpmt/sync.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct DatagramClient
{
	size_t receiveBufferSize;
	DatagramClientReceive receiveFunction;
	void* handle;
	uint8_t* receiveBuffer;
	Socket* receiveSocket;
	Mutex* receiveMutex;
	Thread* receiveThread;
	volatile bool threadRunning;
};

static void datagramClientReceiveHandler(void* argument)
{
	DatagramClient* client = (DatagramClient*)argument;
	DatagramClientReceive receiveFunction = client->receiveFunction;
	size_t receiveBufferSize = client->receiveBufferSize;
	uint8_t* receiveBuffer = client->receiveBuffer;
	Socket* receiveSocket = client->receiveSocket;
	Mutex* receiveMutex = client->receiveMutex;

	bool result;
	size_t byteCount;

	while (true)
	{
		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false)
		{
			client->threadRunning = false;
			return;
		}

		lockMutex(receiveMutex);

		if (client->threadRunning == false)
		{
			unlockMutex(receiveMutex);
			return;
		}

		result = receiveFunction(
			client,
			receiveBuffer,
			byteCount);

		unlockMutex(receiveMutex);

		if (result == false)
		{
			client->threadRunning = false;
			return;
		}
	}
}

DatagramClient* createDatagramClient(
	const SocketAddress* remoteAddress,
	size_t receiveBufferSize,
	DatagramClientReceive receiveFunction,
	void* handle,
	SslContext* sslContext)
{
	assert(remoteAddress != NULL);
	assert(receiveBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(isNetworkInitialized() == true);

	DatagramClient* client = malloc(sizeof(DatagramClient));

	if (client == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(client);
		return NULL;
	}

	uint8_t addressFamily = getSocketAddressFamily(
		remoteAddress);

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
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		false,
		true,
		sslContext);

	destroySocketAddress(localAddress);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	bool result = connectSocket(
		receiveSocket,
		remoteAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	Mutex* receiveMutex = createMutex();

	if (receiveMutex == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveBufferSize = receiveBufferSize;
	client->receiveFunction = receiveFunction;
	client->handle = handle;
	client->receiveBuffer = receiveBuffer;
	client->receiveSocket = receiveSocket;
	client->receiveMutex = receiveMutex;
	client->threadRunning = true;

	Thread* receiveThread = createThread(
		datagramClientReceiveHandler,
		client);

	if (receiveThread == NULL)
	{
		destroyMutex(receiveMutex);
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}

void destroyDatagramClient(DatagramClient* client)
{
	assert(isNetworkInitialized() == true);

	if (client == NULL)
		return;

	lockMutex(client->receiveMutex);
	client->threadRunning = false;
	shutdownSocket(
		client->receiveSocket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(client->receiveSocket);
	unlockMutex(client->receiveMutex);

	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);
	destroyMutex(client->receiveMutex);
	free(client->receiveBuffer);
	free(client);
}

size_t getDatagramClientReceiveBufferSize(
	const DatagramClient* client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->receiveBufferSize;
}

DatagramClientReceive getDatagramClientReceiveFunction(
	const DatagramClient* client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->receiveFunction;
}

void* getDatagramClientHandle(
	const DatagramClient* client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->handle;
}

Socket* getDatagramClientSocket(
	const DatagramClient* client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->receiveSocket;
}

bool isDatagramClientRunning(
	const DatagramClient* client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->threadRunning;
}

bool datagramClientSend(
	DatagramClient* client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(isNetworkInitialized() == true);

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
