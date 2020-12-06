#include "mpnw/datagram_client.h"
#include "mpmt/thread.h"

#include <string.h>

struct DatagramClient
{
	DatagramClientReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void datagramClientReceiveHandler(
	void* argument)
{
	struct DatagramClient* client =
		(struct DatagramClient*)argument;
	DatagramClientReceive* receiveFunctions =
		client->receiveFunctions;
	size_t receiveFunctionCount =
		client->receiveFunctionCount;
	void* functionArgument =
		client->functionArgument;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	struct Socket* receiveSocket =
		client->receiveSocket;

	size_t byteCount;

	while (true)
	{
		bool result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			client->threadRunning = false;
			return;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			DatagramClientReceive receiveFunction =
				receiveFunctions[functionIndex];

			result = receiveFunction(
				client,
				receiveBuffer,
				byteCount,
				functionArgument);

			if (result == false)
			{
				client->threadRunning = false;
				return;
			}
		}
	}
}

struct DatagramClient* createDatagramClient(
	enum AddressFamily addressFamily,
	const struct SocketAddress* remoteAddress,
	const DatagramClientReceive* _receiveFunctions,
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

	struct DatagramClient* client =
		malloc(sizeof(struct DatagramClient));
	size_t receiveFunctionSize =
		receiveFunctionCount * sizeof(DatagramClientReceive);
	DatagramClientReceive* receiveFunctions = malloc(
		receiveFunctionSize);
	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	struct SocketAddress* localAddress = NULL;

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

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily);

	bool result = bindSocket(
		receiveSocket,
		localAddress);
	result &= connectSocket(
		receiveSocket,
		remoteAddress);

	if (client == NULL ||
		receiveFunctions == NULL ||
		receiveBuffer == NULL ||
		localAddress == NULL ||
		receiveSocket == NULL ||
		result == false)
	{
		free(client);
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

	client->receiveFunctions = receiveFunctions;
	client->receiveFunctionCount = receiveFunctionCount;
	client->functionArgument = functionArgument;
	client->receiveBufferSize = receiveBufferSize;
	client->receiveBuffer = receiveBuffer;
	client->threadRunning = true;
	client->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		datagramClientReceiveHandler,
		client);

	if (receiveThread == NULL)
	{
		free(client);
		free(receiveFunctions);
		free(receiveBuffer);
		destroySocketAddress(localAddress);
		destroySocket(receiveSocket);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}

void destroyDatagramClient(
	struct DatagramClient* client)
{
	if (client == NULL)
		return;

	destroySocket(client->receiveSocket);
	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	free(client->receiveBuffer);
	free(client->receiveFunctions);
	free(client);
}

bool getDatagramClientRunning(
	const struct DatagramClient* client,
	bool* running)
{
	if (client == NULL ||
		running == NULL)
	{
		return false;
	}

	*running = client->threadRunning;
	return true;
}

bool datagramClientSend(
	struct DatagramClient* client,
	const void* buffer,
	size_t count)
{
	if (client == NULL)
		return false;

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
