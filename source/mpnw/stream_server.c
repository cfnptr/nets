#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <time.h>
#include <assert.h>

struct StreamServer
{
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	double receiveTimeoutTime;
	StreamSessionReceive receiveFunction;
	CreateStreamSession createFunction;
	DestroyStreamSession destroyFunction;
	void* functionArgument;
	struct StreamSession* sessionBuffer;
	uint8_t* receiveBuffer;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
	volatile bool threadRunning;
};

struct StreamSession
{
	size_t receiveBufferOffset;
	double lastMessageTime;
	struct StreamServer* server;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
	void* handle;
	volatile bool threadRunning;
};

void streamSessionReceiveHandler(
	void* argument)
{
	struct StreamSession* session =
		(struct StreamSession*)argument;
	struct StreamServer* server =
		session->server;

	double receiveTimeoutTime =
		server->receiveTimeoutTime;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	StreamSessionReceive receiveFunction =
		server->receiveFunction;
	void* functionArgument =
		server->functionArgument;
	struct Socket* receiveSocket =
		session->receiveSocket;

	uint8_t* receiveBuffer =
		server->receiveBuffer +
		session->receiveBufferOffset;

	bool result = server->createFunction(
		session,
		&session->handle);

	if (result == false)
	{
		shutdownSocket(
			receiveSocket,
			SHUTDOWN_RECEIVE_SEND);

		session->threadRunning = false;
		return;
	}

	session->lastMessageTime =
		getCurrentClock();

	size_t byteCount;

	while (session->threadRunning == true)
	{
		double currentTime =
			getCurrentClock();

		if (currentTime - session->lastMessageTime >
			receiveTimeoutTime)
		{
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

	server->destroyFunction(
		session->handle);

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
				session->lastMessageTime = 0.0;
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
	size_t receiveBufferSize,
	double receiveTimeoutTime,
	StreamSessionReceive receiveFunction,
	CreateStreamSession createFunction,
	DestroyStreamSession destroyFunction,
	void* functionArgument,
	struct SslContext* sslContext)
{
	assert(port != NULL);
	assert(sessionBufferSize != 0);
	assert(receiveBufferSize != 0);
	assert(receiveTimeoutTime != 0);
	assert(receiveFunction != NULL);
	assert(createFunction != NULL);
	assert(destroyFunction != NULL);

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
		session.receiveBufferOffset = receiveBufferSize * i;
		session.lastMessageTime = 0.0;
		session.server = server;
		session.receiveSocket = NULL;
		session.receiveThread = NULL;
		session.threadRunning = false;
		sessionBuffer[i] = session;
	}

	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->receiveTimeoutTime = receiveTimeoutTime;
	server->receiveFunction = receiveFunction;
	server->createFunction = createFunction;
	server->destroyFunction = destroyFunction;
	server->functionArgument = functionArgument;
	server->sessionBuffer = sessionBuffer;
	server->receiveBuffer = receiveBuffer;
	server->receiveSocket = receiveSocket;
	server->threadRunning = true;

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

size_t getStreamServerSessionBufferSize(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->sessionBufferSize;
}

size_t getStreamServerReceiveBufferSize(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveBufferSize;
}

double getStreamServerReceiveTimeoutTime(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveTimeoutTime;
}

void* getStreamServerFunctionArgument(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->functionArgument;
}

struct Socket* getStreamServerSocket(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveSocket;
}

const struct StreamServer* getStreamSessionServer(
	const struct StreamSession* session)
{
	assert(session != NULL);
	return session->server;
}

const struct Socket* getStreamSessionSocket(
	const struct StreamSession* session)
{
	assert(session != NULL);
	return session->receiveSocket;
}

void* getStreamSessionHandle(
	const struct StreamSession* session)
{
	assert(session != NULL);
	return session->handle;
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
