#include "mpnw/datagram_server.h"
#include "mpmt/thread.h"

#include <string.h>

struct DatagramServer
{
	DatagramServerReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void datagramServerReceiveHandler(
	void* argument)
{
	struct DatagramServer* server =
		(struct DatagramServer*)argument;
	DatagramServerReceive* receiveFunctions =
		server->receiveFunctions;
	size_t receiveFunctionCount =
		server->receiveFunctionCount;
	void* functionArgument =
		server->functionArgument;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	uint8_t* receiveBuffer =
		server->receiveBuffer;
	struct Socket* receiveSocket =
		server->receiveSocket;

	size_t byteCount;
	struct SocketAddress* remoteAddress;

	while (server->threadRunning == true)
	{
		bool result = socketReceiveFrom(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&remoteAddress,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			sleepThread(1);
			continue;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			DatagramServerReceive receiveFunction =
				receiveFunctions[functionIndex];

			receiveFunction(
				server,
				remoteAddress,
				receiveBuffer,
				byteCount,
				functionArgument);
		}

		destroySocketAddress(
			remoteAddress);
	}
}

struct DatagramServer* createDatagramServer(
	enum AddressFamily addressFamily,
	const char* port,
	const DatagramServerReceive* _receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize)
{
	if (_receiveFunctions == NULL ||
		receiveFunctionCount == 0 ||
		receiveFunctionCount > 256 ||
		receiveBufferSize == 0)
	{
		return NULL;
	}

	struct DatagramServer* server =
		malloc(sizeof(struct DatagramServer));
	size_t receiveFunctionSize =
		receiveFunctionCount * sizeof(DatagramServerReceive);
	DatagramServerReceive* receiveFunctions = malloc(
		receiveFunctionSize);
	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	struct SocketAddress* localAddress = NULL;

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

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily);

	bool result = bindSocket(
		receiveSocket,
		localAddress);

	if (server == NULL ||
		receiveFunctions == NULL ||
		receiveBuffer == NULL ||
		localAddress == NULL ||
		receiveSocket == NULL ||
		result == false)
	{
		free(server);
		free(receiveFunctions);
		free(receiveBuffer);
		destroySocketAddress(localAddress);
		destroySocket(receiveSocket);
		return NULL;
	}

	memcpy(
		receiveFunctions,
		_receiveFunctions,
		receiveFunctionSize);

	server->receiveFunctions = receiveFunctions;
	server->receiveFunctionCount = receiveFunctionCount;
	server->functionArgument = functionArgument;
	server->receiveBufferSize = receiveBufferSize;
	server->receiveBuffer = receiveBuffer;
	server->threadRunning = true;
	server->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		datagramServerReceiveHandler,
		server);

	if (receiveThread == NULL)
	{
		free(server);
		free(receiveFunctions);
		free(receiveBuffer);
		destroySocketAddress(localAddress);
		destroySocket(receiveSocket);
		return NULL;
	}

	server->receiveThread = receiveThread;
	return server;
}

void destroyDatagramServer(
	struct DatagramServer* server)
{
	if (server == NULL)
		return;

	server->threadRunning = false;

	destroySocket(server->receiveSocket);
	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);

	free(server->receiveBuffer);
	free(server->receiveFunctions);
	free(server);
}

bool datagramServerSend(
	struct DatagramServer* server,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address)
{
	if (server == NULL)
		return false;

	return socketSendTo(
		server->receiveSocket,
		buffer,
		count,
		address);
}
