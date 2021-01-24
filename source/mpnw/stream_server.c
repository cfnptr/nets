#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <time.h>
#include <assert.h>

struct StreamServer
{
	struct StreamSession* sessionBuffer;
	size_t sessionBufferSize;
	StreamSessionReceive receiveFunction;
	StreamSessionTimeout timeoutFunction;
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
	volatile bool threadRunning;
	size_t lastMessageTime;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

void streamSessionReceiveHandler(
	void* argument)
{
	struct StreamSession* session =
		(struct StreamSession*)argument;
	struct StreamServer* server =
		session->server;

	StreamSessionReceive receiveFunction =
		server->receiveFunction;
	StreamSessionTimeout timeoutFunction =
		server->timeoutFunction;
	size_t receiveTimeoutTime =
		server->receiveTimeoutTime;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	void* functionArgument =
		server->functionArgument;
	struct Socket* receiveSocket =
		session->receiveSocket;

	uint8_t* receiveBuffer =
		server->receiveBuffer +
		session->receiveBufferOffset;

	bool result;
	size_t byteCount;

	session->lastMessageTime = clock() /
		(CLOCKS_PER_SEC * 1000);

	while (session->threadRunning == true)
	{
		size_t currentTime = clock() /
			(CLOCKS_PER_SEC * 1000);

		if (currentTime - session->lastMessageTime >
			receiveTimeoutTime)
		{
			timeoutFunction(
				session,
				functionArgument);

			break;
		}

		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			sleepThread(1);
			continue;
		}

		result = receiveFunction(
			session,
			receiveBuffer,
			byteCount,
			functionArgument);

		if (result == false)
			break;

		session->lastMessageTime = currentTime;
	}

	shutdownSocket(
		receiveSocket,
		SHUTDOWN_RECEIVE_SEND);
	session->threadRunning = false;
}

static void streamServerAcceptHandler(
	void* argument)
{
	struct StreamServer* server =
		(struct StreamServer*)argument;
	struct StreamSession* sessionBuffer =
		server->sessionBuffer;
	size_t sessionBufferSize =
		server->sessionBufferSize;
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

		result = false;

		for (size_t i = 0; i < sessionBufferSize; i++)
		{
			struct StreamSession* session =
				&sessionBuffer[i];

			if (session->threadRunning == false)
			{
				if (session->receiveSocket != NULL)
				{
					joinThread(session->receiveThread);
					destroyThread(session->receiveThread);
					destroySocket(session->receiveSocket);
				}

				session->threadRunning = true;
				session->lastMessageTime = 0;
				session->receiveSocket = acceptedSocket;

				struct Thread* receiveThread = createThread(
					streamSessionReceiveHandler,
					session);

				if (receiveThread == NULL)
					break;

				session->receiveThread = receiveThread;

				result = true;
				break;
			}
		}

		if (result == false)
			destroySocket(acceptedSocket);
	}

	server->threadRunning = false;
}

struct StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	StreamSessionReceive receiveFunction,
	StreamSessionTimeout timeoutFunction,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext)
{
	assert(port != NULL);
	assert(sessionBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(timeoutFunction != NULL);
	assert(receiveTimeoutTime != 0);
	assert(receiveBufferSize != 0);

	struct StreamServer* server = malloc(
		sizeof(struct StreamServer));

	if (server == NULL)
		return NULL;

	struct StreamSession* sessionBuffer = malloc(
		sessionBufferSize * sizeof(struct StreamSession));

	if (sessionBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	uint8_t* receiveBuffer = malloc(sizeof(uint8_t) *
		sessionBufferSize * receiveBufferSize);

	if (receiveBuffer == NULL)
	{
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	struct SocketAddress* localAddress;

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
		abort();
	}

	if (localAddress == NULL)
	{
		free(receiveBuffer);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		true,
		false,
		sslContext);

	destroySocketAddress(
		localAddress);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession session;
		session.server = server;
		session.receiveBufferOffset = receiveBufferSize * i;
		session.threadRunning = false;
		session.lastMessageTime = 0;
		session.receiveSocket = NULL;
		session.receiveThread = NULL;
		sessionBuffer[i] = session;
	}

	server->sessionBuffer = sessionBuffer;
	server->sessionBufferSize = sessionBufferSize;
	server->receiveFunction = receiveFunction;
	server->timeoutFunction = timeoutFunction;
	server->receiveTimeoutTime = receiveTimeoutTime;
	server->functionArgument = functionArgument;
	server->receiveBufferSize = receiveBufferSize;
	server->receiveBuffer = receiveBuffer;
	server->threadRunning = true;
	server->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		streamServerAcceptHandler,
		server);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
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

	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);
	destroySocket(server->receiveSocket);

	struct StreamSession* sessionBuffer =
		server->sessionBuffer;
	size_t sessionBufferSize =
		server->sessionBufferSize;

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession session =
			sessionBuffer[i];

		if (session.receiveSocket != NULL)
		{
			session.threadRunning = false;

			joinThread(session.receiveThread);
			destroyThread(session.receiveThread);
			destroySocket(session.receiveSocket);
		}
	}

	free(server->receiveBuffer);
	free(server->sessionBuffer);
	free(server);
}

const struct Socket* getStreamServerSocket(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveSocket;
}

bool streamSessionSend(
	struct StreamSession* session,
	const void* buffer,
	size_t count)
{
	assert(session != NULL);
	assert(buffer != NULL);
	assert(count != 0);

	return socketSend(
		session->receiveSocket,
		buffer,
		count);
}
