#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <stdlib.h>
#include "time.h"

struct StreamSession
{
	bool running;
	size_t receiveBufferSize;
	StreamSessionReceive sessionReceive;
	struct Socket* socket;
	struct SocketAddress* socketAddress;
	char* receiveBuffer;
	struct Thread* receiveThread;
};
struct StreamServer
{
	bool running;
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	size_t messageTimeoutTime;
	StreamServerAccept serverAccept;
	StreamSessionReceive sessionReceive;
	struct StreamSession** sessionBuffer;
	struct Socket* socket;
	struct Thread* acceptThread;
};

void streamSessionReceive(
	void* argument)
{
	struct StreamSession* session =
		(struct StreamSession*)argument;

	size_t receiveBufferSize = session->receiveBufferSize;
	StreamSessionReceive sessionReceive = session->sessionReceive;
	struct Socket* socket = session->socket;
	char* receiveBuffer = session->receiveBuffer;

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
			session->running = false;
			return;
		}

		result = sessionReceive(
			count,
			socket,
			receiveBuffer);

		if (!result)
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
	struct Socket* socket,
	struct SocketAddress* socketAddress)
{
	struct StreamSession* session =
		malloc(sizeof(struct StreamSession));

	if (!session)
		return NULL;

	session->running = true;
	session->receiveBufferSize = receiveBufferSize;
	session->sessionReceive = sessionReceive;
	session->socket = socket;
	session->socketAddress = socketAddress;

	char* receiveBuffer = malloc(
		receiveBufferSize * sizeof(char));

	if (!receiveBuffer)
	{
		free(session);
		return NULL;
	}

	session->receiveBuffer = receiveBuffer;

	struct Thread* receiveThread = createThread(
		streamSessionReceive,
		session);

	if (!receiveThread)
	{
		free(receiveBuffer);
		free(session);
		return NULL;
	}

	session->receiveThread = receiveThread;
	return session;
}
void destroyStreamSession(
	struct StreamSession* session)
{
	destroySocket(
		session->socket);
	joinThread(
		session->receiveThread);
	destroyThread(
		session->receiveThread);
	destroySocketAddress(
		session->socketAddress);
	free(session->receiveBuffer);
	free(session);
}

bool addStreamSession(
	struct StreamSession** sessionBuffer,
	size_t sessionBufferSize,
	struct Socket* socket,
	struct SocketAddress* socketAddress,
	StreamSessionReceive sessionReceive,
	size_t receiveBufferSize)
{
	bool created = false;

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession* session =
			sessionBuffer[i];

		if (session && !session->running)
		{
			destroyStreamSession(session);
			sessionBuffer[i] = session = NULL;
		}

		if (!created && !session)
			continue;

		struct StreamSession* _session = createStreamSession(
			receiveBufferSize,
			sessionReceive,
			socket,
			socketAddress);

		if (!_session)
			continue;

		sessionBuffer[i] = _session;
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
	size_t messageTimeoutTime = server->messageTimeoutTime;
	StreamServerAccept serverAccept = server->serverAccept;
	StreamSessionReceive sessionReceive = server->sessionReceive;
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

		if (!result)
		{
			server->running = false;
			return;
		}

		if (!setSocketReceiveTimeout(socket, messageTimeoutTime) ||
			!setSocketSendTimeout(socket, messageTimeoutTime))
		{
			destroySocket(acceptedSocket);
			destroySocketAddress(acceptedAddress);
			return;
		}

		result = serverAccept(
			acceptedSocket,
			acceptedAddress);

		if (!result)
		{
			destroySocket(acceptedSocket);
			destroySocketAddress(acceptedAddress);
			continue;
		}

		result = addStreamSession(
			sessionBuffer,
			sessionBufferSize,
			acceptedSocket,
			acceptedAddress,
			sessionReceive,
			receiveBufferSize);

		if (!result)
		{
			destroySocket(acceptedSocket);
			destroySocketAddress(acceptedAddress);
		}
	}
}

struct StreamServer* createStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	uint32_t messageTimeoutTime,
	StreamServerAccept serverAccept,
	StreamSessionReceive sessionReceive)
{
	if (!sessionBufferSize ||
		!receiveBufferSize ||
		!serverAccept ||
		!sessionReceive)
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
	if (!listenSocket(socket))
	{
		destroySocket(socket);
		return NULL;
	}

	struct StreamServer* server =
		malloc(sizeof(struct StreamServer));

	if (!server) 
	{
		destroySocket(socket);
		return NULL;
	}

	server->running = true;
	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->messageTimeoutTime = messageTimeoutTime;
	server->serverAccept = serverAccept;
	server->sessionReceive = sessionReceive;
	server->socket = socket;

	struct StreamSession** sessionBuffer = calloc(
		sessionBufferSize,
		sizeof(struct StreamSession*));

	if (!sessionBuffer)
	{
		destroySocket(socket);
		free(server);
		return NULL;
	}

	server->sessionBuffer = sessionBuffer;

	struct Thread* acceptThread = createThread(
		streamServerAccept,
		server);

	if (!acceptThread)
	{
		destroySocket(socket);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	server->acceptThread = acceptThread;
	return server;
}
void destroyStreamServer(
	struct StreamServer* server)
{
	if (server)
	{
		destroySocket(
			server->socket);
		joinThread(
			server->acceptThread);
		destroyThread(
			server->acceptThread);

		size_t sessionBufferSize = server->sessionBufferSize;
		struct StreamSession** sessionBuffer = server->sessionBuffer;

		for (size_t i = 0; i < sessionBufferSize; i++)
		{
			struct StreamSession* session =
				sessionBuffer[i];

			if (session)
				destroyStreamSession(session);
		}

		free(sessionBuffer);
	}

	free(server);
}

bool getStreamServerRunning(
	const struct StreamServer* server,
	bool* running)
{
	if (!server)
		return false;

	*running = server->running;
	return true;
}
