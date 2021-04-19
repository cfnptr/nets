#include "mpnw/stream_server.h"
#include "mpmt/thread.h"

#include <stdio.h>

struct StreamSession
{
	Socket* receiveSocket;
	void* handle;
	double lastMessageTime;
	bool isSslAccepted;
};

struct StreamServer
{
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	double timeoutTime;
	OnStreamSessionCreate onCreate;
	OnStreamSessionDestroy onDestroy;
	OnStreamSessionReceive onReceive;
	OnStreamSessionUpdate onUpdate;
	void* handle;
	uint8_t* receiveBuffer;
	StreamSession* sessionBuffer;
	size_t sessionCount;
	Socket* acceptSocket;
};

StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* service,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	double timeoutTime,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionUpdate onUpdate,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext* sslContext)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(sessionBufferSize != 0);
	assert(receiveBufferSize != 0);
	assert(timeoutTime != 0);
	assert(onCreate != NULL);
	assert(onDestroy != NULL);
	assert(onUpdate != NULL);
	assert(onReceive != NULL);
	assert(isNetworkInitialized() == true);

	StreamServer* server = malloc(sizeof(StreamServer));

	if (server == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	StreamSession* sessionBuffer = malloc(
		sessionBufferSize * sizeof(StreamSession));

	if (sessionBuffer == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	SocketAddress* localAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service);
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

	Socket* acceptSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		true,
		false,
		sslContext);

	destroySocketAddress(localAddress);

	if (acceptSocket == NULL)
	{
		free(sessionBuffer);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->sessionBufferSize = sessionBufferSize;
	server->receiveBufferSize = receiveBufferSize;
	server->timeoutTime = timeoutTime;
	server->onCreate = onCreate;
	server->onDestroy = onDestroy;
	server->onUpdate = onUpdate;
	server->onReceive = onReceive;
	server->handle = handle;
	server->sessionBuffer = sessionBuffer;
	server->sessionCount = 0;
	server->receiveBuffer = receiveBuffer;
	server->acceptSocket = acceptSocket;
	return server;
}

void destroyStreamServer(StreamServer* server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	StreamSession* sessionBuffer = server->sessionBuffer;
	size_t sessionCount = server->sessionCount;
	OnStreamSessionDestroy onDestroy = server->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession* session = &sessionBuffer[i];
		Socket* receiveSocket = session->receiveSocket;

		onDestroy(
			server,
			session);
		shutdownSocket(
			receiveSocket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	}

	shutdownSocket(
		server->acceptSocket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(server->acceptSocket);
	free(server->receiveBuffer);
	free(sessionBuffer);
	free(server);
}

size_t getStreamServerSessionBufferSize(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->sessionBufferSize;
}

OnStreamSessionCreate getStreamServerOnCreate(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onCreate;
}

OnStreamSessionDestroy getStreamServerOnDestroy(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onDestroy;
}

OnStreamSessionUpdate getStreamServerOnUpdate(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onUpdate;
}

OnStreamSessionReceive getStreamServerOnReceive(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onReceive;
}

size_t getStreamServerReceiveBufferSize(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->receiveBufferSize;
}

double getStreamServerTimeoutTime(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->timeoutTime;
}

void* getStreamServerHandle(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->handle;
}

Socket* getStreamServerSocket(
	const StreamServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->acceptSocket;
}

Socket* getStreamSessionSocket(
	const StreamSession* session)
{
	assert(session != NULL);
	assert(isNetworkInitialized() == true);
	return session->receiveSocket;
}

void* getStreamSessionHandle(
	const StreamSession* session)
{
	assert(session != NULL);
	assert(isNetworkInitialized() == true);
	return session->handle;
}

void updateStreamServer(StreamServer* server)
{
	assert(server != NULL);

	StreamSession* sessionBuffer = server->sessionBuffer;
	size_t sessionBufferSize = server->sessionBufferSize;
	size_t sessionCount = server->sessionCount;
	double timeoutTime = server->timeoutTime;
	double currentTime = getCurrentClock();
	uint8_t* receiveBuffer = server->receiveBuffer;
	size_t receiveBufferSize = server->receiveBufferSize;
	OnStreamSessionCreate onCreate = server->onCreate;
	OnStreamSessionDestroy onDestroy = server->onDestroy;
	OnStreamSessionUpdate onUpdate = server->onUpdate;
	OnStreamSessionReceive onReceive = server->onReceive;
	Socket* serverSocket = server->acceptSocket;
	bool isServerSocketSsl = getSocketSslContext(serverSocket) != NULL;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession* session = &sessionBuffer[i];
		Socket* receiveSocket = session->receiveSocket;

		if (currentTime - session->lastMessageTime > timeoutTime)
			goto DESTROY_SESSION;

		if (session->isSslAccepted == false)
		{
			bool result = acceptSslSocket(receiveSocket);

			if(result == true)
				session->isSslAccepted = true;
			else
				continue;
		}

		bool result = onUpdate(
			server,
			session);

		if (result == false)
			goto DESTROY_SESSION;

		size_t byteCount;

		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false)
			continue;

		result = onReceive(
			server,
			session,
			receiveBuffer,
			byteCount);

		if (result == true)
		{
			session->lastMessageTime = currentTime;
			continue;
		}

	DESTROY_SESSION:
		onDestroy(
			server,
			session);
		shutdownSocket(
			receiveSocket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);

		for (size_t j = i + 1; j < sessionCount; j++)
			sessionBuffer[j - 1] = sessionBuffer[j];

		if (i > 0)
			i--;

		sessionCount--;
	}

	Socket* acceptedSocket = acceptSocket(serverSocket);

	if (acceptedSocket != NULL)
	{
		if (sessionCount < sessionBufferSize)
		{
			void* session;

			bool result = onCreate(
				server,
				acceptedSocket,
				&session);

			if (result == true)
			{
				StreamSession streamSession;
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
					RECEIVE_SEND_SOCKET_SHUTDOWN);
				destroySocket(acceptedSocket);
			}
		}
		else
		{
			shutdownSocket(
				acceptedSocket,
				RECEIVE_SEND_SOCKET_SHUTDOWN);
			destroySocket(acceptedSocket);
		}
	}

	server->sessionCount = sessionCount;
}

bool streamSessionSend(
	StreamSession* session,
	const void* buffer,
	size_t count)
{
	assert(session != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(isNetworkInitialized() == true);

	return socketSend(
		session->receiveSocket,
		buffer,
		count);
}
