#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <assert.h>

struct StreamClient
{
	volatile bool running;
	size_t receiveBufferSize;
	StreamClientReceive receiveFunction;
	void* receiveArgument;
	struct Socket* socket;
	uint8_t * receiveBuffer;
	struct Thread* receiveThread;
};

void streamClientReceive(void* argument)
{
	struct StreamClient* client =
		(struct StreamClient*)argument;

	size_t receiveBufferSize = client->receiveBufferSize;
	StreamClientReceive receiveFunction = client->receiveFunction;
	void* receiveArgument = client->receiveArgument;
	struct Socket* socket = client->socket;
	uint8_t* receiveBuffer = client->receiveBuffer;

	while (true)
	{
		size_t count;

		bool result = socketReceive(
			socket,
			receiveBuffer,
			receiveBufferSize,
			&count);

		if (result == false || count == 0)
		{
			shutdownSocket(
				socket,
				SHUTDOWN_RECEIVE_SEND);
			client->running = false;
			return;
		}

		result = receiveFunction(
			count,
			socket,
			receiveBuffer,
			receiveArgument);

		if (result == false)
		{
			shutdownSocket(
				socket,
				SHUTDOWN_RECEIVE_SEND);
			client->running = false;
			return;
		}
	}
}

struct StreamClient* createStreamClient(
	const struct SocketAddress* address,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* receiveArgument)
{
	assert(address != NULL);
	assert(receiveBufferSize > 0);
	assert(receiveFunction != NULL);

	struct StreamClient* client =
		malloc(sizeof(struct StreamClient));
	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (client == NULL ||
		receiveBuffer == NULL)
	{
		abort();
	}

	enum AddressFamily family =
		getSocketAddressFamily(address);

	struct Socket* socket = createSocket(
		STREAM_SOCKET,
		family);

	bindSocket(socket, address);

	client->running = true;
	client->receiveBufferSize = receiveBufferSize;
	client->receiveFunction = receiveFunction;
	client->receiveArgument = receiveArgument;
	client->socket = socket;
	client->receiveBuffer = receiveBuffer;

	struct Thread* receiveThread = createThread(
		streamClientReceive,
		client);

	client->receiveThread = receiveThread;
	return client;
}
void destroyStreamClient(
	struct StreamClient* client)
{
	if (client)
	{
		destroySocket(client->socket);
		joinThread(client->receiveThread);
		destroyThread(client->receiveThread);
		free(client->receiveBuffer);
	}

	free(client);
}

bool isStreamClientRunning(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->running;
}