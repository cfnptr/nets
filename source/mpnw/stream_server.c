#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <stdlib.h>
#include "time.h"

struct StreamSession
{
	bool running;
	size_t receiveBufferSize;
	SessionReceiveHandler receiveHandler;
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
	SessionAcceptHandler acceptHandler;
	SessionReceiveHandler receiveHandler;
	struct StreamSession** sessionBuffer;
	struct Socket* socket;
	struct Thread* acceptThread;
};

void *mpnwStreamSessionReceive(
	void* argument)
{
	struct StreamSession* session =
		(struct StreamSession*)argument;

	size_t receiveBufferSize = session->receiveBufferSize;
	SessionReceiveHandler receiveHandler = session->receiveHandler;
	struct Socket* socket = session->socket;
	char* receiveBuffer = session->receiveBuffer;

	while (true)
	{
		size_t count;

		bool result = mpnwSocketReceive(
			socket,
			receiveBuffer,
			receiveBufferSize,
			&count);

		if(!result || count == 0)
		{
			mpnwShutdownSocket(
				socket,
				SHUTDOWN_RECEIVE_SEND);
			session->running = false;
			return NULL;
		}

		result = receiveHandler(
			count,
			socket,
			receiveBuffer);

		if(!result)
		{
			mpnwShutdownSocket(
				socket,
				SHUTDOWN_RECEIVE_SEND);
			session->running = false;
			return NULL;
		}
	}
}

struct StreamSession* mpnwCreateStreamSession(
	size_t receiveBufferSize,
	SessionReceiveHandler receiveHandler,
	struct Socket* socket,
	struct SocketAddress* socketAddress)
{
	struct StreamSession* session =
		malloc(sizeof(struct StreamSession));
	session->running = true;
	session->receiveBufferSize = receiveBufferSize;
	session->receiveHandler = receiveHandler;
	session->socket = socket;
	session->socketAddress = socketAddress;

	char* receiveBuffer = malloc(
		receiveBufferSize * sizeof(char));
	session->receiveBuffer = receiveBuffer;

	struct Thread* receiveThread = mpmtCreateThread(
		mpnwStreamSessionReceive,
		session);

	if(!receiveThread)
	{
		free(receiveBuffer);
		free(session);
		return NULL;
	}

	session->receiveThread = receiveThread;
	return session;
}
void mpnwDestroyStreamSession(
	struct StreamSession* session)
{
	mpnwDestroySocket(
		session->socket);
	mpmtJoinThread(
		session->receiveThread,
		NULL);
	mpmtDestroyThread(
		session->receiveThread);
	mpnwDestroySocketAddress(
		session->socketAddress);

	free(session->receiveBuffer);
	free(session);
}

bool mpnwAddStreamSession(
	struct StreamSession** sessionBuffer,
	size_t sessionBufferSize,
	struct Socket* socket,
	struct SocketAddress* socketAddress,
	SessionReceiveHandler receiveHandler,
	size_t receiveBufferSize)
{
	bool created = false;

	for (size_t i = 0; i < sessionBufferSize; i++)
	{
		struct StreamSession* session =
			sessionBuffer[i];

		if (session && !session->running)
		{
			mpnwDestroyStreamSession(session);
			sessionBuffer[i] = session = NULL;
		}

		if(!created && !session)
			continue;

		sessionBuffer[i] = mpnwCreateStreamSession(
			receiveBufferSize,
			receiveHandler,
			socket,
			socketAddress);
		created = true;
	}

	return created;
}
void *mpnwStreamServerAccept(
	void* argument)
{
	struct StreamServer* server =
		(struct StreamServer*)argument;

	size_t sessionBufferSize = server->sessionBufferSize;
	size_t receiveBufferSize = server->receiveBufferSize;
	SessionAcceptHandler acceptHandler = server->acceptHandler;
	SessionReceiveHandler receiveHandler = server->receiveHandler;
	struct StreamSession** sessionBuffer = server->sessionBuffer;
	struct Socket* socket = server->socket;

	struct Socket* acceptedSocket;
	struct SocketAddress* acceptedAddress;

	while (true)
	{
		bool result = mpnwAcceptSocket(
			socket,
			&acceptedSocket,
			&acceptedAddress);

		if(!result)
		{
			server->running = false;
			return NULL;
		}

		result = acceptHandler(
			acceptedSocket,
			acceptedAddress);

		if(!result)
		{
			mpnwDestroySocket(acceptedSocket);
			mpnwDestroySocketAddress(acceptedAddress);
			continue;
		}

		result = mpnwAddStreamSession(
			sessionBuffer,
			sessionBufferSize,
			acceptedSocket,
			acceptedAddress,
			receiveHandler,
			receiveBufferSize);

		if(!result)
		{
			mpnwDestroySocket(acceptedSocket);
			mpnwDestroySocketAddress(acceptedAddress);
		}
	}
}

struct StreamServer* mpnwCreateStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t sessionTimeoutTime,
	size_t receiveBufferSize,
	SessionAcceptHandler acceptHandler,
	SessionReceiveHandler receiveHandler)
{
	if(!sessionBufferSize ||
		!receiveBufferSize ||
		!acceptHandler ||
		!receiveHandler)
	{
		return NULL;
	}

	enum AddressFamily family;

	bool result = mpnwGetSocketAddressFamily(
		address,
		&family);

	if(!result)
		return NULL;

	struct Socket* socket = mpnwCreateSocket(
		STREAM_SOCKET,
		family);

	if(!socket)
		return NULL;

	if(!mpnwSetSocketReceiveTimeout(socket, sessionTimeoutTime))
	{
		mpnwDestroySocket(socket);
		return NULL;
	}
	if(!mpnwSetSocketSendTimeout(socket, sessionTimeoutTime))
	{
		mpnwDestroySocket(socket);
		return NULL;
	}
	if(!mpnwBindSocket(socket, address))
	{
		mpnwDestroySocket(socket);
		return NULL;
	}
	if(!mpnwListenSocket(socket))
	{
		mpnwDestroySocket(socket);
		return NULL;
	}

	struct StreamServer* server =
		malloc(sizeof(struct StreamServer));
	server->running = true;
	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->acceptHandler = acceptHandler;
	server->receiveHandler = receiveHandler;
	server->socket = socket;

	struct StreamSession** sessionBuffer = calloc(
		sessionBufferSize,
		sizeof(struct StreamSession*));
	server->sessionBuffer = sessionBuffer;

	struct Thread* acceptThread = mpmtCreateThread(
		mpnwStreamServerAccept,
		server);

	if(!acceptThread)
	{
		mpnwDestroySocket(socket);
		free(sessionBuffer);
		free(server);
		return NULL;
	}

	server->acceptThread = acceptThread;
	return server;
}
void mpnwDestroyStreamServer(
	struct StreamServer* server)
{
	if(server)
	{
		mpnwDestroySocket(
			server->socket);
		mpmtJoinThread(
			server->acceptThread,
			NULL);
		mpmtDestroyThread(
			server->acceptThread);

		size_t sessionBufferSize = server->sessionBufferSize;
		struct StreamSession** sessionBuffer = server->sessionBuffer;

		for (size_t i = 0; i < sessionBufferSize; i++)
		{
			struct StreamSession* session =
				sessionBuffer[i];
			if(session)
				mpnwDestroyStreamSession(session);
		}

		free(sessionBuffer);
	}

	free(server);
}

bool mpnwGetStreamServerRunning(
	const struct StreamServer* server,
	bool* running)
{
	if(!server)
		return false;

	*running = server->running;
	return true;
}
