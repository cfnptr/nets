#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <assert.h>

struct StreamClient
{
	volatile bool running;
	size_t receiveBufferSize;
	StreamClientReceive clientReceive;
	struct Socket* socket;
	char* receiveBuffer;
	struct Thread* receiveThread;
};

void streamClientReceive(
	void* argument)
{
	struct StreamClient* client =
		(struct StreamClient*)argument;

	size_t receiveBufferSize = client->receiveBufferSize;
	StreamClientReceive clientReceive = client->clientReceive;
	struct Socket* socket = client->socket;
	char* receiveBuffer = client->receiveBuffer;

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

		result = clientReceive(
			count,
			socket,
			receiveBuffer);

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
	struct SocketAddress* address,
	size_t receiveBufferSize,
	uint32_t messageTimeoutTime,
	StreamClientReceive clientReceive)
{
	assert(address != NULL);
	assert(receiveBufferSize > 0);
	assert(clientReceive != NULL);

	struct StreamClient* client =
		malloc(sizeof(struct StreamClient));
	char* receiveBuffer = malloc(
		receiveBufferSize * sizeof(char));

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

	setSocketReceiveTimeout(socket, messageTimeoutTime);
	setSocketSendTimeout(socket, messageTimeoutTime);

	client->running = true;
	client->receiveBufferSize = receiveBufferSize;
	client->clientReceive = clientReceive;
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