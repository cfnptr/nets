#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

struct StreamClient
{
	bool running;
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

		if (!result || count == 0)
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

		if (!result)
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
	if (!receiveBufferSize ||
		!clientReceive)
	{
		return NULL;
	}

	enum AddressFamily family;

	bool result = getSocketAddressFamily(
		address,
		&family);

	if (!result)
		return NULL;

	struct Socket* socket = createSocket(
		STREAM_SOCKET,
		family);

	if (!socket)
		return NULL;

	if (!bindSocket(socket, address))
	{
		destroySocket(socket);
		return NULL;
	}
	if (!setSocketReceiveTimeout(socket, messageTimeoutTime) ||
		!setSocketSendTimeout(socket, messageTimeoutTime))
	{
		destroySocket(socket);
		return NULL;
	}

	struct StreamClient* client =
		malloc(sizeof(struct StreamClient));

	if (!client)
	{
		destroySocket(socket);
		return NULL;
	}

	client->running = true;
	client->receiveBufferSize = receiveBufferSize;
	client->clientReceive = clientReceive;
	client->socket = socket;

	char* receiveBuffer = malloc(
		receiveBufferSize * sizeof(char));

	if (!receiveBuffer)
	{
		destroySocket(socket);
		free(client);
		return NULL;
	}

	client->receiveBuffer = receiveBuffer;

	struct Thread* receiveThread = createThread(
		streamClientReceive,
		client);

	if (!receiveThread)
	{
		destroySocket(socket);
		free(receiveBuffer);
		free(clientReceive);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}
void destroyStreamClient(
	struct StreamClient* client)
{
	if (client)
	{
		destroySocket(
			client->socket);
		joinThread(
			client->receiveThread);
		destroyThread(
			client->receiveThread);

		free(client->receiveBuffer);
	}

	free(client);
}

bool getStreamClientRunning(
	const struct StreamClient* server,
	bool* running)
{
	if (!server)
		return false;

	*running = server->running;
	return true;
}