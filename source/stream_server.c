#include "mpnw/stream_server.h"

#include "mpmt/mutex.h"
#include "mpmt/thread.h"

struct StreamSession
{
	struct Socket* receiveSocket;
	void* handle;
	double lastMessageTime;
	bool isSslAccepted;
};

struct StreamServer
{
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	double receiveTimeoutTime;
	StreamSessionReceive receiveFunction;
	StreamSessionCreate createFunction;
	StreamSessionDestroy destroyFunction;
	void* handle;
	uint8_t* receiveBuffer;
	struct StreamSession* sessionBuffer;
	struct Socket* acceptSocket;
	struct Thread* receiveThread;
	volatile bool threadsRunning;
};

static void streamServerReceiveHandler(
	void* argument)
{
	struct StreamServer* server =
		(struct StreamServer*)argument;
	size_t sessionBufferSize =
		server->sessionBufferSize;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	double receiveTimeoutTime =
		server->receiveTimeoutTime;
	StreamSessionReceive receiveFunction =
		server->receiveFunction;
	StreamSessionCreate createFunction =
		server->createFunction;
	StreamSessionDestroy destroyFunction =
		server->destroyFunction;
	uint8_t* receiveBuffer =
		server->receiveBuffer;
	struct StreamSession* sessionBuffer =
		server->sessionBuffer;
	struct Socket* serverSocket =
		server->acceptSocket;
	bool isServerSocketSsl =
		getSocketSslContext(serverSocket) != NULL;

	size_t sessionCount = 0;

	while (server->threadsRunning == true)
	{
		bool shouldSleep = true;
		double currentTime = getCurrentClock();

		for (size_t i = 0; i < sessionCount; i++)
		{
			struct StreamSession* session =
				&sessionBuffer[i];
			struct Socket* receiveSocket =
				session->receiveSocket;

			if (currentTime - session->lastMessageTime > receiveTimeoutTime)
				goto DESTROY_SESSION;

			if (session->isSslAccepted == false)
			{
				bool result = acceptSslSocket(
					receiveSocket);

				if(result == true)
					session->isSslAccepted = true;
				else
					continue;
			}

			size_t byteCount;

			bool result = socketReceive(
				receiveSocket,
				receiveBuffer,
				receiveBufferSize,
				&byteCount);

			if (result == false)
				continue;

			result = receiveFunction(
				server,
				session,
				receiveBuffer,
				byteCount);

			if (result == true)
			{
				session->lastMessageTime = currentTime;
				shouldSleep = false;
				continue;
			}

		DESTROY_SESSION:
			destroyFunction(
				server,
				session);
			shutdownSocket(
				receiveSocket,
				SHUTDOWN_RECEIVE_SEND);
			destroySocket(receiveSocket);

			for (size_t j = i + 1; j < sessionCount; j++)
				sessionBuffer[j - 1] = sessionBuffer[j];

			if (i > 0)
				i--;

			sessionCount--;
			shouldSleep = false;
		}

		struct Socket* acceptedSocket = acceptSocket(
			serverSocket);

		if (acceptedSocket != NULL)
		{
			if (sessionCount < sessionBufferSize)
			{
				void* session;

				bool result = createFunction(
					server,
					acceptedSocket,
					&session);

				if (result == true)
				{
					struct StreamSession streamSession;
					streamSession.receiveSocket = acceptedSocket;
					streamSession.handle = session;
					streamSession.lastMessageTime = getCurrentClock();
					streamSession.isSslAccepted = !isServerSocketSsl;
					sessionBuffer[sessionCount++] = streamSession;
				}
				else
				{
					shutdownSocket(
						acceptedSocket,
						SHUTDOWN_RECEIVE_SEND);
					destroySocket(acceptedSocket);
				}

				shouldSleep = false;
			}
			else
			{
				shutdownSocket(
					acceptedSocket,
					SHUTDOWN_RECEIVE_SEND);
				destroySocket(acceptedSocket);
			}
		}

		if (shouldSleep == true)
			sleepThread(0.001);
	}

	for (size_t i = 0; i < sessionCount; i++)
	{
		struct StreamSession* session =
			&sessionBuffer[i];
		struct Socket* receiveSocket =
			session->receiveSocket;

		destroyFunction(
			server,
			session);
		shutdownSocket(
			receiveSocket,
			SHUTDOWN_RECEIVE_SEND);
		destroySocket(receiveSocket);
	}
}

struct StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	double receiveTimeoutTime,
	StreamSessionReceive receiveFunction,
	StreamSessionCreate createFunction,
	StreamSessionDestroy destroyFunction,
	void* handle,
	struct SslContext* sslContext)
{
	assert(port != NULL);
	assert(sessionBufferSize != 0);
	assert(receiveBufferSize != 0);
	assert(receiveTimeoutTime != 0);
	assert(receiveFunction != NULL);
	assert(createFunction != NULL);
	assert(destroyFunction != NULL);
	assert(isNetworkInitialized() == true);

	struct StreamServer* server = malloc(
		sizeof(struct StreamServer));

	if (server == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	struct StreamSession* sessionBuffer = malloc(
		sessionBufferSize * sizeof(struct StreamSession));

	if (sessionBuffer == NULL)
	{
		free(receiveBuffer);
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
		free(sessionBuffer);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	if (localAddress == NULL)
	{
		free(sessionBuffer);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	struct Socket* acceptSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		true,
		false,
		sslContext);

	destroySocketAddress(
		localAddress);

	if (acceptSocket == NULL)
	{
		free(sessionBuffer);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->receiveTimeoutTime = receiveTimeoutTime;
	server->receiveFunction = receiveFunction;
	server->createFunction = createFunction;
	server->destroyFunction = destroyFunction;
	server->handle = handle;
	server->sessionBuffer = sessionBuffer;
	server->receiveBuffer = receiveBuffer;
	server->acceptSocket = acceptSocket;
	server->threadsRunning = true;

	struct Thread* receiveThread = createThread(
		streamServerReceiveHandler,
		server);

	if (receiveThread == NULL)
	{
		destroySocket(acceptSocket);
		free(sessionBuffer);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveThread = receiveThread;
	return server;
}

void destroyStreamServer(
	struct StreamServer* server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	server->threadsRunning = false;
	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);

	shutdownSocket(
		server->acceptSocket,
		SHUTDOWN_RECEIVE_SEND);
	destroySocket(server->acceptSocket);

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

StreamSessionReceive getStreamServerReceiveFunction(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->receiveFunction;
}

StreamSessionCreate getStreamServerCreateFunction(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->createFunction;
}

StreamSessionDestroy getStreamServerDestroyFunction(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->destroyFunction;
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

void* getStreamServerHandle(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->handle;
}

struct Socket* getStreamServerSocket(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->acceptSocket;
}

struct Socket* getStreamSessionSocket(
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
	struct StreamSession* streamSession,
	const void* buffer,
	size_t count)
{
	assert(streamSession != NULL);
	assert(buffer != NULL);
	assert(count != 0);

	return socketSend(
		streamSession->receiveSocket,
		buffer,
		count);
}
