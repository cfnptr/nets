#include "mpnw/stream_socket.h"

#include "mpmt/thread.h"
#include "mpmt/xalloc.h"

#include <stdlib.h>
#include <assert.h>

struct StreamClient
{
	size_t receiveBufferSize;
	StreamClientReceive receiveFunction;
	StreamClientStop stopFunction;
	void* customData;
	uint8_t* receiveBuffer;
	struct Socket* streamSocket;
	struct Thread* receiveThread;
	bool threadStarted;
	volatile bool threadRunning;
};

struct StreamServer
{
	size_t receiveBufferSize;
	StreamServerAccept serverAcceptFunction;
	StreamServerStop serverStopFunction;
	StreamClientReceive clientReceiveFunction;
	StreamClientStop clientStopFunction;
	void* customData;
	struct Socket* streamSocket;
	struct Thread* acceptThread;
	bool threadStarted;
	volatile bool threadRunning;
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
				streamClient);
			shutdownSocket(
				streamSocket,
				SHUTDOWN_RECEIVE_SEND);
			streamClient->threadRunning = false;
			return;
		}

		result = receiveFunction(
			streamClient,
			receiveCount,
			receiveBuffer);

		if (result == false)
		{
			stopFunction(
				streamClient);
			shutdownSocket(
				streamSocket,
				SHUTDOWN_RECEIVE_SEND);
			streamClient->threadRunning = false;
			return;
		}
	}
}

struct StreamClient* createStreamClient(
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	StreamClientStop stopFunction,
	void* customData)
{
	assert(receiveBufferSize > 0);
	assert(receiveFunction != NULL);
	assert(stopFunction != NULL);

	struct StreamClient* streamClient =
		xmalloc(sizeof(struct StreamClient));

	streamClient->receiveBufferSize =
		receiveBufferSize;
	streamClient->receiveFunction =
		receiveFunction;
	streamClient->stopFunction =
		stopFunction;
	streamClient->customData =
		customData;

	streamClient->receiveBuffer = xmalloc(
		receiveBufferSize * sizeof(uint8_t));

	streamClient->streamSocket = NULL;
	streamClient->receiveThread = NULL;
	streamClient->threadStarted = false;
	streamClient->threadRunning = false;

	return streamClient;
}
void destroyStreamClient(
	struct StreamClient* client)
{
	if (client != NULL)
	{
		if (client->threadStarted == true)
		{
			destroySocket(client->streamSocket);
			joinThread(client->receiveThread);
			destroyThread(client->receiveThread);
		}

		free(client->receiveBuffer);
	}

	free(client);
}

size_t getStreamClientReceiveBufferSize(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->receiveBufferSize;
}
void* getStreamClientCustomData(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->customData;
}

bool isStreamClientStarted(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->threadStarted;
}
bool isStreamClientRunning(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->threadRunning;
}

void startStreamClient(
	struct StreamClient* client,
	enum AddressFamily addressFamily)
{
	assert(client != NULL);
	assert(client->threadStarted != true);

	struct Socket* streamSocket = createSocket(
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
		streamSocket,
		address);
	destroySocketAddress(
		address);

	client->streamSocket = streamSocket;
	client->threadStarted = true;
	client->threadRunning = true;

	struct Thread* receiveThread = createThread(
		streamClientReceive,
		client);

	client->receiveThread = receiveThread;
}

struct SocketAddress* getStreamClientLocalAddress(
	const struct StreamClient* client)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	return getSocketLocalAddress(
		client->streamSocket);
}
struct SocketAddress* getStreamClientRemoteAddress(
	const struct StreamClient* client)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	return getSocketRemoteAddress(
		client->streamSocket);
}

size_t getStreamClientReceiveTimeout(
	const struct StreamClient* client)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	return getSocketReceiveTimeout(
		client->streamSocket);
}
void setStreamClientReceiveTimeout(
	struct StreamClient* client,
	size_t milliseconds)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	setSocketReceiveTimeout(
		client->streamSocket,
		milliseconds);
}

size_t getStreamClientSendTimeout(
	const struct StreamClient* client)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	return getSocketSendTimeout(
		client->streamSocket);
}
void setStreamClientSendTimeout(
	struct StreamClient* client,
	size_t milliseconds)
{
	assert(client != NULL);
	assert(client->threadStarted == true);

	setSocketSendTimeout(
		client->streamSocket,
		milliseconds);
}

bool streamClientSend(
	struct StreamClient* client,
	void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);
	assert(count > 0);
	assert(client->threadStarted == true);

	return socketSend(
		client->streamSocket,
		buffer,
		count);
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
	void* customData =
		streamServer->customData;
	struct Socket* streamSocket =
		streamServer->streamSocket;

	bool result = false;
	struct Socket* acceptedSocket = NULL;

	while (true)
	{
		acceptedSocket = acceptSocket(
			streamSocket);

		if (acceptedSocket == NULL)
		{
			serverStopFunction(
				streamServer);
			streamServer->threadRunning = false;
			return;
		}

		struct StreamClient* streamClient =
			xmalloc(sizeof(struct StreamClient));

		streamClient->receiveBufferSize =
			receiveBufferSize;
		streamClient->receiveFunction =
			clientReceiveFunction;
		streamClient->stopFunction =
			clientStopFunction;
		streamClient->customData =
			customData;
		streamClient->streamSocket =
			acceptedSocket;

		streamClient->receiveBuffer = xmalloc(
			receiveBufferSize * sizeof(uint8_t));

		streamClient->receiveThread = NULL;
		streamClient->threadStarted = true;
		streamClient->threadRunning = true;

		result = serverAcceptFunction(
			streamServer,
			streamClient);

		if (result == true)
		{
			struct Thread* receiveThread = createThread(
				streamClientReceive,
				streamClient);

			streamClient->receiveThread = receiveThread;
		}
		else
		{
			destroySocket(acceptedSocket);
			free(streamClient->receiveBuffer);
			free(streamClient);
		}
	}
}

struct StreamServer* createStreamServer(
	size_t receiveBufferSize,
	StreamServerAccept serverAcceptFunction,
	StreamServerStop serverStopFunction,
	StreamClientReceive clientReceiveFunction,
	StreamClientStop clientStopFunction,
	void* customData)
{
	assert(receiveBufferSize > 0);
	assert(serverAcceptFunction != NULL);
	assert(serverStopFunction != NULL);
	assert(clientReceiveFunction != NULL);
	assert(clientStopFunction != NULL);

	struct StreamServer* streamServer =
		xmalloc(sizeof(struct StreamServer));

	streamServer->receiveBufferSize =
		receiveBufferSize;
	streamServer->serverAcceptFunction =
		serverAcceptFunction;
	streamServer->serverStopFunction =
		serverStopFunction;
	streamServer->clientReceiveFunction =
		clientReceiveFunction;
	streamServer->clientStopFunction =
		clientStopFunction;
	streamServer->customData =
		customData;

	streamServer->streamSocket = NULL;
	streamServer->acceptThread = NULL;
	streamServer->threadStarted = false;
	streamServer->threadRunning = false;

	return streamServer;
}
void destroyStreamServer(
	struct StreamServer* server)
{
	if (server != NULL && server->threadStarted == true)
	{
		destroySocket(server->streamSocket);
		joinThread(server->acceptThread);
		destroyThread(server->acceptThread);
	}

	free(server);
}

size_t getStreamServerReceiveBufferSize(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveBufferSize;
}
void* getStreamServerCustomData(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->customData;
}

bool isStreamServerStarted(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->threadStarted;
}
bool isStreamServerRunning(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->threadRunning;
}

void startStreamServer(
	struct StreamServer* server,
	enum AddressFamily addressFamily,
	const char* portNumber)
{
	assert(server != NULL);
	assert(portNumber != NULL);
	assert(server->threadStarted != true);

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
	destroySocketAddress(
		address);

	server->streamSocket = streamSocket;
	server->threadStarted = true;
	server->threadRunning = true;

	struct Thread* acceptThread = createThread(
		streamServerAccept,
		server);

	server->acceptThread = acceptThread;
}

struct SocketAddress* getStreamServerLocalAddress(
	const struct StreamServer* server)
{
	assert(server != NULL);
	assert(server->threadStarted == true);

	return getSocketLocalAddress(
		server->streamSocket);
}
