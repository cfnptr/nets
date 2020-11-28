#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <stdlib.h>
#include <assert.h>

struct StreamSession
{
	volatile bool running;
	size_t receiveBufferSize;
	StreamSessionReceive sessionReceive;
	void* receiveArgument;
	struct Socket* socket;
	uint8_t* receiveBuffer;
	struct Thread* receiveThread;
};
struct StreamServer
{
	volatile bool running;
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	StreamServerAccept acceptFunction;
	StreamSessionReceive receiveFunction;
	void* acceptArgument;
	void* receiveArgument;
	struct StreamSession** sessionBuffer;
	struct Socket* socket;
	struct Thread* acceptThread;
};

void streamSessionReceive(void* argument)
{
	struct StreamSession* session =
		(struct StreamSession*)argument;

	size_t receiveBufferSize = session->receiveBufferSize;
	StreamSessionReceive sessionReceive = session->sessionReceive;
	void* receiveArgument = session->receiveArgument;
	struct Socket* socket = session->socket;
	uint8_t* receiveBuffer = session->receiveBuffer;

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
			session->running = false;
			return;
		}

		result = sessionReceive(
			count,
			socket,
			receiveBuffer,
			receiveArgument);

		if (result == false)
		{
			shutdownSocket(
				socket,
				SHUTDOWN_RECEIVE_SEND);
			session->running = false;
			return;
		}
	}
}

struct StreamSession* createStreamSession(
	size_t receiveBufferSize,
	StreamSessionReceive sessionReceive,
	void* receiveArgument,
	struct Socket* socket)
{
	struct StreamSession* session =
		malloc(sizeof(struct StreamSession));
	uint8_t* receiveBuffer =
		malloc(receiveBufferSize * sizeof(uint8_t));

	if (session == NULL ||
		receiveBuffer == NULL)
	{
		abort();
	}

	session->running = true;
	session->receiveBufferSize = receiveBufferSize;
	session->sessionReceive = sessionReceive;
	session->receiveArgument = receiveArgument;
	session->socket = socket;
	session->receiveBuffer = receiveBuffer;

	struct Thread* receiveThread = createThread(
		streamSessionReceive,
		session);

	session->receiveThread = receiveThread;
	return session;
}
void destroyStreamSession(
	struct StreamSession* session)
{
	destroySocket(session->socket);
	joinThread(session->receiveThread);
	destroyThread(session->receiveThread);

	free(session->receiveBuffer);
	free(session);
}

bool addStreamSession(
	struct StreamSession** sessionBuffer,
	size_t sessionBufferSize,
	struct Socket* socket,
	StreamSessionReceive sessionReceive,
	void* receiveArgument,
	size_t receiveBufferSize)
{
	bool created = false;

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession* session =
			sessionBuffer[i];

		if (session != NULL && session->running == false)
		{
			destroyStreamSession(session);
			sessionBuffer[i] = session = NULL;
		}

		if (created == false &&
			session == NULL)
		{
			continue;
		}

		sessionBuffer[i] = createStreamSession(
			receiveBufferSize,
			sessionReceive,
			receiveArgument,
			socket);

		created = true;
	}

	return created;
}
void streamServerAccept(
	void* argument)
{
	struct StreamServer* server =
		(struct StreamServer*)argument;

	size_t sessionBufferSize = server->sessionBufferSize;
	size_t receiveBufferSize = server->receiveBufferSize;
	StreamServerAccept acceptFunction = server->acceptFunction;
	StreamSessionReceive receiveFunction = server->receiveFunction;
	void* acceptArgument = server->acceptArgument;
	void* receiveArgument = server->receiveArgument;
	struct StreamSession** sessionBuffer = server->sessionBuffer;
	struct Socket* socket = server->socket;

	struct Socket* acceptedSocket;
	struct SocketAddress* acceptedAddress;

	while (true)
	{
		bool result = acceptSocket(
			socket,
			&acceptedSocket,
			&acceptedAddress);

		if (result == false)
		{
			server->running = false;
			return;
		}

		result = acceptFunction(
			acceptedSocket,
			acceptedAddress,
			acceptArgument);

		destroySocketAddress(
			acceptedAddress);

		if (result == false)
		{
			destroySocket(
				acceptedSocket);
			continue;
		}

		result = addStreamSession(
			sessionBuffer,
			sessionBufferSize,
			acceptedSocket,
			receiveFunction,
			receiveArgument,
			receiveBufferSize);

		if (result == false)
		{
			destroySocket(
				acceptedSocket);
		}
	}
}

struct StreamServer* createStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	StreamServerAccept acceptFunction,
	StreamSessionReceive receiveFunction,
	void* acceptArgument,
	void* receiveArgument)
{
	assert(address != NULL);
	assert(sessionBufferSize > 0);
	assert(receiveBufferSize > 0);
	assert(acceptFunction != NULL);
	assert(receiveFunction != NULL);

	struct StreamServer* server =
		malloc(sizeof(struct StreamServer));
	struct StreamSession** sessionBuffer = calloc(
		sessionBufferSize,
		sizeof(struct StreamSession*));

	if (server == NULL ||
		sessionBuffer == NULL)
	{
		abort();
	}

	enum AddressFamily family =
		getSocketAddressFamily(address);

	struct Socket* socket = createSocket(
		STREAM_SOCKET,
		family);

	bindSocket(socket, address);
	listenSocket(socket);

	server->running = true;
	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->acceptFunction = acceptFunction;
	server->receiveFunction = receiveFunction;
	server->acceptArgument = acceptArgument;
	server->receiveArgument = receiveArgument;
	server->socket = socket;
	server->sessionBuffer = sessionBuffer;

	struct Thread* acceptThread = createThread(
		streamServerAccept,
		server);

	server->acceptThread = acceptThread;
	return server;
}
void destroyStreamServer(
	struct StreamServer* server)
{
	if (server != NULL)
	{
		destroySocket(server->socket);
		joinThread(server->acceptThread);
		destroyThread(server->acceptThread);

		size_t sessionBufferSize = server->sessionBufferSize;
		struct StreamSession** sessionBuffer = server->sessionBuffer;

		for (size_t i = 0; i < sessionBufferSize; i++)
		{
			if (sessionBuffer[i] != NULL)
				destroyStreamSession(sessionBuffer[i]);
		}

		free(sessionBuffer);
	}

	free(server);
}

bool isStreamServerRunning(
	const struct StreamServer* server)
{
	assert(server != NULL);
	return server->running;
}
