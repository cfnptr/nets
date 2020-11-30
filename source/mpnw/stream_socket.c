#include "mpnw/stream_socket.h"
#include "mpmt/thread.h"

#include <stdlib.h>
#include <assert.h>

struct StreamClient
{
	volatile bool running;
	size_t receiveBufferSize;
	StreamClientReceive receiveFunction;
	StreamClientStop stopFunction;
	void* receiveArgument;
	void* stopArgument;
	struct Socket* streamSocket;
	uint8_t* receiveBuffer;
	struct Thread* receiveThread;
};

struct StreamServer
{
	volatile bool running;
	size_t receiveBufferSize;
	StreamServerAccept serverAcceptFunction;
	StreamServerStop serverStopFunction;
	StreamClientReceive clientReceiveFunction;
	StreamClientStop clientStopFunction;
	void* serverAcceptArgument;
	void* serverStopArgument;
	void* clientReceiveArgument;
	void* clientStopArgument;
	struct Socket* streamSocket;
	struct Thread* acceptThread;
};

void streamClientReceive(void* argument)
{
	assert(argument != NULL);

	struct StreamClient* streamClient =
		(struct StreamClient*)argument;

	size_t receiveBufferSize =
		streamClient->receiveBufferSize;
	StreamClientReceive receiveFunction =
		streamClient->receiveFunction;
	StreamClientStop stopFunction =
		streamClient->stopFunction;
	void* receiveArgument =
		streamClient->receiveArgument;
	void* stopArgument =
		streamClient->stopArgument;
	struct Socket* streamSocket =
		streamClient->streamSocket;
	uint8_t* receiveBuffer =
		streamClient->receiveBuffer;

	bool result = false;
	size_t receiveCount = 0;

	while (true)
	{
		result = socketReceive(
			streamSocket,
			receiveBuffer,
			receiveBufferSize,
			&receiveCount);

		if (result == false)
		{
			stopFunction(
				streamClient,
				stopArgument);
			shutdownSocket(
				streamSocket,
				SHUTDOWN_RECEIVE_SEND);
			streamClient->running = false;
			return;
		}

		result = receiveFunction(
			streamClient,
			receiveCount,
			receiveBuffer,
			receiveArgument);

		if (result == false)
		{
			stopFunction(
				streamClient,
				stopArgument);
			shutdownSocket(
				streamSocket,
				SHUTDOWN_RECEIVE_SEND);
			streamClient->running = false;
			return;
		}
	}
}

struct StreamClient* createStreamClient(
	enum AddressFamily addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	StreamClientStop stopFunction,
	void* receiveArgument,
	void* stopArgument)
{
	assert(receiveBufferSize > 0);
	assert(receiveFunction != NULL);
	assert(stopFunction != NULL);

	struct StreamClient* streamClient =
		malloc(sizeof(struct StreamClient));
	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (streamClient == NULL ||
		receiveBuffer == NULL)
	{
		abort();
	}

	streamClient->running = true;
	streamClient->receiveBufferSize =
		receiveBufferSize;
	streamClient->receiveFunction =
		receiveFunction;
	streamClient->stopFunction =
		stopFunction;
	streamClient->receiveArgument =
		receiveArgument;
	streamClient->stopArgument =
		stopArgument;
	streamClient->receiveBuffer =
		receiveBuffer;

	struct Socket* socket = createSocket(
		STREAM_SOCKET,
		addressFamily);

	struct SocketAddress* address;

	if (addressFamily == INTERNET_PROTOCOL_V4)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_PORT);
	}
	else if (addressFamily == INTERNET_PROTOCOL_V6)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_PORT);
	}
	else
	{
		abort();
	}

	bindSocket(
		socket,
		address);

	destroySocketAddress(address);
	streamClient->streamSocket = socket;


	struct Thread* receiveThread = createThread(
		streamClientReceive,
		streamClient);

	streamClient->receiveThread = receiveThread;
	return streamClient;
}
void destroyStreamClient(
	struct StreamClient* client)
{
	if (client)
	{
		destroySocket(client->streamSocket);
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

struct SocketAddress* getStreamClientLocalAddress(
	const struct StreamClient* client)
{
	assert(client != NULL);

	return getSocketLocalAddress(
		client->streamSocket);
}
struct SocketAddress* getStreamClientRemoteAddress(
	const struct StreamClient* client)
{
	assert(client != NULL);

	return getSocketRemoteAddress(
		client->streamSocket);
}

size_t getStreamClientReceiveTimeout(
	const struct StreamClient* client)
{
	assert(client != NULL);

	return getSocketReceiveTimeout(
		client->streamSocket);
}
void setStreamClientReceiveTimeout(
	struct StreamClient* client,
	size_t milliseconds)
{
	assert(client != NULL);

	setSocketReceiveTimeout(
		client->streamSocket,
		milliseconds);
}

size_t getStreamClientSendTimeout(
	const struct StreamClient* client)
{
	assert(client != NULL);

	return getSocketSendTimeout(
		client->streamSocket);
}
void setStreamClientSendTimeout(
	struct StreamClient* client,
	size_t milliseconds)
{
	assert(client != NULL);

	setSocketSendTimeout(
		client->streamSocket,
		milliseconds);
}

void streamServerAccept(
	void* argument)
{
	assert(argument != NULL);

	struct StreamServer* streamServer =
		(struct StreamServer*)argument;

	size_t receiveBufferSize =
		streamServer->receiveBufferSize;
	StreamServerAccept serverAcceptFunction =
		streamServer->serverAcceptFunction;
	StreamServerStop serverStopFunction =
		streamServer->serverStopFunction;
	StreamClientReceive clientReceiveFunction =
		streamServer->clientReceiveFunction;
	StreamClientStop clientStopFunction =
		streamServer->clientStopFunction;
	void* serverAcceptArgument =
		streamServer->serverAcceptArgument;
	void* serverStopArgument =
		streamServer->serverStopArgument;
	void* clientReceiveArgument =
		streamServer->clientReceiveArgument;
	void* clientStopArgument =
		streamServer->clientStopArgument;
	struct Socket* streamSocket =
		streamServer->streamSocket;

	struct Socket* acceptedSocket = NULL;

	while (true)
	{
		acceptedSocket = acceptSocket(
			streamSocket);

		if (acceptedSocket == NULL)
		{
			serverStopFunction(
				streamServer,
				serverStopArgument);
			streamServer->running = false;
			return;
		}

		struct StreamClient* streamClient =
			malloc(sizeof(struct StreamClient));
		uint8_t* receiveBuffer = malloc(
			receiveBufferSize * sizeof(uint8_t));

		if (streamClient == NULL ||
			receiveBuffer == NULL)
		{
			abort();
		}

		streamClient->running = true;
		streamClient->receiveBufferSize =
			receiveBufferSize;
		streamClient->receiveFunction =
			clientReceiveFunction;
		streamClient->stopFunction =
			clientStopFunction;
		streamClient->receiveArgument =
			clientReceiveArgument;
		streamClient->stopArgument =
			clientStopArgument;
		streamClient->receiveBuffer =
			receiveBuffer;
		streamClient->streamSocket =
			acceptedSocket;

		struct Thread* receiveThread = createThread(
			streamClientReceive,
			streamClient);

		streamClient->receiveThread = receiveThread;

		serverAcceptFunction(
			streamServer,
			streamClient,
			serverAcceptArgument);
	}
}

struct StreamServer* createStreamServer(
	enum AddressFamily addressFamily,
	const char* portNumber,
	size_t receiveBufferSize,
	StreamServerAccept serverAcceptFunction,
	StreamServerStop serverStopFunction,
	StreamClientReceive clientReceiveFunction,
	StreamClientStop clientStopFunction,
	void* serverAcceptArgument,
	void* serverStopArgument,
	void* clientReceiveArgument,
	void* clientStopArgument)
{
	assert(receiveBufferSize > 0);
	assert(serverAcceptFunction != NULL);
	assert(serverStopFunction != NULL);
	assert(clientReceiveFunction != NULL);
	assert(clientStopFunction != NULL);

	struct StreamServer* streamServer =
		malloc(sizeof(struct StreamServer));

	if (streamServer == NULL)
		abort();

	streamServer->running = true;
	streamServer->serverAcceptFunction =
		serverAcceptFunction;
	streamServer->serverStopFunction =
		serverStopFunction;
	streamServer->clientReceiveFunction =
		clientReceiveFunction;
	streamServer->clientStopFunction =
		clientStopFunction;
	streamServer->serverAcceptArgument =
		serverAcceptArgument;
	streamServer->serverStopArgument =
		serverStopArgument;
	streamServer->clientReceiveArgument =
		clientReceiveArgument;
	streamServer->clientStopArgument =
		clientStopArgument;

	struct Socket* streamSocket = createSocket(
		STREAM_SOCKET,
		addressFamily);

	struct SocketAddress* address;

	if (addressFamily == INTERNET_PROTOCOL_V4)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			portNumber);
	}
	else if (addressFamily == INTERNET_PROTOCOL_V6)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			portNumber);
	}
	else
	{
		abort();
	}

	bindSocket(
		streamSocket,
		address);
	listenSocket(
		streamSocket);

	destroySocketAddress(address);
	streamServer->streamSocket = streamSocket;

	struct Thread* acceptThread = createThread(
		streamServerAccept,
		streamServer);

	streamServer->acceptThread = acceptThread;
	return streamServer;
}
void destroyStreamServer(
	struct StreamServer* server)
{
	if (server != NULL)
	{
		destroySocket(server->streamSocket);
		joinThread(server->acceptThread);
		destroyThread(server->acceptThread);
	}

	free(server);
}

bool isStreamServerRunning(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->running;
}
