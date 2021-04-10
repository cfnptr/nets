#include "mpnw/datagram_server.h"

#include "mpmt/sync.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct DatagramServer
{
	size_t receiveBufferSize;
	DatagramServerReceive receiveFunction;
	void* handle;
	uint8_t* receiveBuffer;
	SocketAddress* remoteAddress;
	Socket* receiveSocket;
	Mutex* receiveMutex;
	Thread* receiveThread;
	volatile bool threadRunning;
};

static void datagramServerReceiveHandler(void* argument)
{
	DatagramServer* server = (DatagramServer*)argument;
	DatagramServerReceive receiveFunction = server->receiveFunction;
	size_t receiveBufferSize = server->receiveBufferSize;
	uint8_t* receiveBuffer = server->receiveBuffer;
	SocketAddress* remoteAddress = server->remoteAddress;
	Socket* receiveSocket = server->receiveSocket;
	Mutex* receiveMutex = server->receiveMutex;

	bool result;
	size_t byteCount;

	while (true)
	{
		result = socketReceiveFrom(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			remoteAddress,
			&byteCount);

		if (result == false)
		{
			server->threadRunning = false;
			return;
		}

		lockMutex(receiveMutex);

		if (server->threadRunning == false)
		{
			unlockMutex(receiveMutex);
			return;
		}

		result = receiveFunction(
			server,
			remoteAddress,
			receiveBuffer,
			byteCount);

		unlockMutex(receiveMutex);

		if (result == false)
		{
			server->threadRunning = false;
			return;
		}
	}
}

DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* port,
	size_t receiveBufferSize,
	DatagramServerReceive receiveFunction,
	void* handle,
	SslContext* sslContext)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(port != NULL);
	assert(receiveBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(isNetworkInitialized() == true);

	DatagramServer* server = malloc(sizeof(DatagramServer));

	if (server == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	SocketAddress* localAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			port);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			port);
	}
	else
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	if (localAddress == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		false,
		true,
		sslContext);

	if (receiveSocket == NULL)
	{
		destroySocketAddress(localAddress);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	Mutex* receiveMutex = createMutex();

	if (receiveMutex == NULL)
	{
		destroySocket(receiveSocket);
		destroySocketAddress(localAddress);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveBufferSize = receiveBufferSize;
	server->receiveFunction = receiveFunction;
	server->handle = handle;
	server->receiveBuffer = receiveBuffer;
	server->remoteAddress = localAddress;
	server->receiveSocket = receiveSocket;
	server->receiveMutex = receiveMutex;
	server->threadRunning = true;

	Thread* receiveThread = createThread(
		datagramServerReceiveHandler,
		server);

	if (receiveThread == NULL)
	{
		destroyMutex(receiveMutex);
		destroySocket(receiveSocket);
		destroySocketAddress(localAddress);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveThread = receiveThread;
	return server;
}

void destroyDatagramServer(DatagramServer* server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	lockMutex(server->receiveMutex);
	server->threadRunning = false;
	shutdownSocket(
		server->receiveSocket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(server->receiveSocket);
	unlockMutex(server->receiveMutex);

	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);
	destroyMutex(server->receiveMutex);
	destroySocketAddress(server->remoteAddress);
	free(server->receiveBuffer);
	free(server);
}

size_t getDatagramServerReceiveBufferSize(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->receiveBufferSize;
}

DatagramServerReceive getDatagramServerReceiveFunction(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->receiveFunction;
}

void* getDatagramServerHandle(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->handle;
}

Socket* getDatagramServerSocket(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->receiveSocket;
}

bool isDatagramServerRunning(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->threadRunning;
}

bool datagramServerSend(
	DatagramServer* server,
	const void* buffer,
	size_t count,
	const SocketAddress* address)
{
	assert(server != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(address != NULL);
	assert(isNetworkInitialized() == true);

	return socketSendTo(
		server->receiveSocket,
		buffer,
		count,
		address);
}
