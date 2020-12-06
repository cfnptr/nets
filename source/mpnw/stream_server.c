#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <time.h>
#include <assert.h>
#include <string.h>

struct StreamServer
{
	struct StreamSession* sessionBuffer;
	size_t sessionBufferSize;
	StreamSessionReceive* receiveFunctions;
	size_t receiveFunctionCount;
	size_t receiveTimeoutTime;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

struct StreamSession
{
	struct StreamServer* server;
	size_t receiveBufferOffset;
	bool hasRunningSocket;
	volatile size_t lastMessageTime;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void streamSessionReceiveHandler(
	void* argument)
{
	assert(argument != NULL);

	struct StreamSession* session =
		(struct StreamSession*)argument;
	struct StreamServer* server =
		session->server;

	StreamSessionReceive* receiveFunctions =
		server->receiveFunctions;
	size_t receiveFunctionCount =
		server->receiveFunctionCount;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	void* functionArgument =
		server->functionArgument;
	struct Socket* receiveSocket =
		session->receiveSocket;

	uint8_t* receiveBuffer =
		server->receiveBuffer +
		session->receiveBufferOffset;

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
			shutdownSocket(
				receiveSocket,
				SHUTDOWN_RECEIVE_SEND);
			session->lastMessageTime = 0;
			return;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			StreamSessionReceive receiveFunction =
				receiveFunctions[functionIndex];

			result = receiveFunction(
				session,
				receiveBuffer,
				byteCount,
				functionArgument);

			if (result == false)
			{
				shutdownSocket(
					receiveSocket,
					SHUTDOWN_RECEIVE_SEND);
				session->lastMessageTime = 0;
				return;
			}
		}
	}
}

static void streamServerAcceptHandler(
	void* argument)
{
	assert(argument != NULL);

	struct StreamServer* server =
		(struct StreamServer*)argument;
	struct StreamSession* sessionBuffer =
		server->sessionBuffer;
	size_t sessionBufferSize =
		server->sessionBufferSize;
	size_t receiveTimeoutTime =
		server->receiveTimeoutTime;
	struct Socket* receiveSocket =
		server->receiveSocket;

	struct Socket* acceptedSocket;

	while (server->threadRunning == true)
	{
		bool result = acceptSocket(
			receiveSocket,
			&acceptedSocket);

		if (result == false)
		{
			sleepThread(1);
			continue;
		}

		size_t currentTime = clock() /
			(CLOCKS_PER_SEC * 1000);
		result = false;

		for (size_t i = 0; i < sessionBufferSize; i++)
		{
			struct StreamSession* session =
				&sessionBuffer[i];

			size_t deltaMessageTime =
				currentTime - session->lastMessageTime;

			if (session->hasRunningSocket == true &&
				deltaMessageTime > receiveTimeoutTime)
			{
				destroySocket(session->receiveSocket);
				joinThread(session->receiveThread);
				destroyThread(session->receiveThread);
				session->hasRunningSocket = false;
			}

			if (session->hasRunningSocket == false)
			{
				session->receiveSocket = acceptedSocket;

				struct Thread* receiveThread = createThread(
					streamSessionReceiveHandler,
					session);

				if (receiveThread == NULL)
					break;

				session->receiveThread = receiveThread;
				session->hasRunningSocket = true;

				result = true;
				break;
			}
		}

		if (result == false)
			destroySocket(acceptedSocket);
	}
}

struct StreamServer* createStreamServer(
	const struct SocketAddress* localAddress,
	size_t sessionBufferSize,
	const StreamSessionReceive* _receiveFunctions,
	size_t receiveFunctionCount,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(localAddress != NULL);
	assert(sessionBufferSize > 0);
	assert(_receiveFunctions != NULL);
	assert(receiveFunctionCount > 0);
	assert(receiveFunctionCount <= 256);
	assert(receiveBufferSize > 0);

	struct StreamServer* server =
		malloc(sizeof(struct StreamServer));

	if (server == NULL)
		return NULL;

	struct StreamSession* sessionBuffer = malloc(
		sessionBufferSize * sizeof(struct StreamSession));

	if (sessionBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession session;

		session.server = server;
		session.receiveBufferOffset = receiveBufferSize * i;
		session.hasRunningSocket = false;
		session.lastMessageTime = 0;
		session.receiveSocket = NULL;
		session.receiveThread = NULL;

		sessionBuffer[i] = session;
	}

	size_t receiveFunctionSize =
		receiveFunctionCount * sizeof(StreamSessionReceive);
	StreamSessionReceive* receiveFunctions = malloc(
		receiveFunctionSize);

	if (receiveFunctions == NULL)
	{
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	memcpy(
		receiveFunctions,
		_receiveFunctions,
		receiveFunctionSize);

	server->sessionBuffer = sessionBuffer;
	server->sessionBufferSize = sessionBufferSize;
	server->receiveFunctions = receiveFunctions;
	server->receiveFunctionCount = receiveFunctionCount;
	server->receiveTimeoutTime = receiveTimeoutTime;
	server->functionArgument = functionArgument;
	server->receiveFunctionCount = receiveFunctionCount;
	server->receiveBufferSize = receiveBufferSize;

	server->threadRunning = true;

	uint8_t* receiveBuffer = malloc(sizeof(uint8_t) *
		sessionBufferSize * receiveBufferSize);

	if (receiveBuffer == NULL)
	{
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	server->receiveBuffer = receiveBuffer;

	enum AddressFamily addressFamily;

	bool result = getSocketAddressFamily(
		localAddress,
		&addressFamily);

	if (result == false)
	{
		free(receiveBuffer);
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	result = bindSocket(
		receiveSocket,
		localAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	result = listenSocket(
		receiveSocket);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	server->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		streamServerAcceptHandler,
		server);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(receiveFunctions);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	server->receiveThread = receiveThread;
	return server;
}

void destroyStreamServer(
	struct StreamServer* server)
{
	if (server == NULL)
		return;

	server->threadRunning = false;

	shutdownSocket(
		server->receiveSocket,
		SHUTDOWN_RECEIVE_SEND);
	destroySocket(server->receiveSocket);

	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);

	struct StreamSession* sessionBuffer =
		server->sessionBuffer;
	size_t sessionBufferSize =
		server->sessionBufferSize;

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession session =
			sessionBuffer[i];

		if (session.hasRunningSocket == true)
		{
			destroySocket(session.receiveSocket);
			joinThread(session.receiveThread);
			destroyThread(session.receiveThread);
		}
	}

	free(server->receiveBuffer);
	free(server->sessionBuffer);
	free(server);
}

bool streamSessionSend(
	struct StreamSession* session,
	const void* buffer,
	size_t count)
{
	assert(session != NULL);
	assert(buffer != NULL);

	return socketSend(
		session->receiveSocket,
		buffer,
		count);
}
