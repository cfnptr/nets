#include "mpnw/stream_server.h"
#include <stdio.h>

struct StreamSession
{
	Socket receiveSocket;
	void* handle;
	bool isSslAccepted;
};

struct StreamServer
{
	size_t sessionBufferSize;
	size_t receiveBufferSize;
	OnStreamSessionCreate onCreate;
	OnStreamSessionDestroy onDestroy;
	OnStreamSessionReceive onReceive;
	OnStreamSessionUpdate onUpdate;
	void* handle;
	uint8_t* receiveBuffer;
	StreamSession sessionBuffer;
	size_t sessionCount;
	Socket acceptSocket;
};

MpnwResult createStreamServer(
	AddressFamily addressFamily,
	const char* service,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionUpdate onUpdate,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamServer* _streamServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(sessionBufferSize != 0);
	assert(receiveBufferSize != 0);
	assert(onCreate != NULL);
	assert(onDestroy != NULL);
	assert(onUpdate != NULL);
	assert(onReceive != NULL);
	assert(_streamServer != NULL);
	assert(isNetworkInitialized() == true);

	StreamServer streamServer = malloc(
		sizeof(struct StreamServer));

	if (streamServer == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(streamServer);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	StreamSession sessionBuffer = malloc(
		sessionBufferSize * sizeof(struct StreamSession));

	if (sessionBuffer == NULL)
	{
		free(receiveBuffer);
		free(streamServer);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service,
			&socketAddress);
	}
	else
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service,
			&socketAddress);
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(sessionBuffer);
		free(receiveBuffer);
		free(streamServer);
		return mpnwResult;
	}

	Socket acceptSocket;

	mpnwResult = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		true,
		false,
		sslContext,
		&acceptSocket);

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(sessionBuffer);
		free(receiveBuffer);
		free(streamServer);
		return mpnwResult;
	}

	streamServer->sessionBufferSize = sessionBufferSize;
	streamServer->receiveBufferSize = receiveBufferSize;
	streamServer->onCreate = onCreate;
	streamServer->onDestroy = onDestroy;
	streamServer->onUpdate = onUpdate;
	streamServer->onReceive = onReceive;
	streamServer->handle = handle;
	streamServer->sessionBuffer = sessionBuffer;
	streamServer->sessionCount = 0;
	streamServer->receiveBuffer = receiveBuffer;
	streamServer->acceptSocket = acceptSocket;

	*_streamServer = streamServer;
	return SUCCESS_MPNW_RESULT;
}

void destroyStreamServer(StreamServer server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	StreamSession sessionBuffer = server->sessionBuffer;
	size_t sessionCount = server->sessionCount;
	OnStreamSessionDestroy onDestroy = server->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession session = &sessionBuffer[i];
		Socket receiveSocket = session->receiveSocket;

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

size_t getStreamServerSessionBufferSize(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->sessionBufferSize;
}

size_t getStreamServerReceiveBufferSize(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->receiveBufferSize;
}

OnStreamSessionCreate getStreamServerOnCreate(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onCreate;
}

OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onDestroy;
}

OnStreamSessionUpdate getStreamServerOnUpdate(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onUpdate;
}

OnStreamSessionReceive getStreamServerOnReceive(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onReceive;
}

void* getStreamServerHandle(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->handle;
}

Socket getStreamServerSocket(StreamServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->acceptSocket;
}

Socket getStreamSessionSocket(StreamSession session)
{
	assert(session != NULL);
	assert(isNetworkInitialized() == true);
	return session->receiveSocket;
}

void* getStreamSessionHandle(StreamSession session)
{
	assert(session != NULL);
	assert(isNetworkInitialized() == true);
	return session->handle;
}

bool updateStreamServer(StreamServer server)
{
	assert(server != NULL);

	bool isUpdated = false;

	StreamSession sessionBuffer = server->sessionBuffer;
	size_t sessionBufferSize = server->sessionBufferSize;
	size_t sessionCount = server->sessionCount;
	uint8_t* receiveBuffer = server->receiveBuffer;
	size_t receiveBufferSize = server->receiveBufferSize;
	OnStreamSessionCreate onCreate = server->onCreate;
	OnStreamSessionDestroy onDestroy = server->onDestroy;
	OnStreamSessionUpdate onUpdate = server->onUpdate;
	OnStreamSessionReceive onReceive = server->onReceive;
	Socket serverSocket = server->acceptSocket;
	bool isServerSocketSsl = getSocketSslContext(serverSocket) != NULL;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession session = &sessionBuffer[i];
		Socket receiveSocket = session->receiveSocket;

		if (session->isSslAccepted == false)
		{
			bool result = acceptSslSocket(receiveSocket);

			if (result == true)
			{
				session->isSslAccepted = true;
				isUpdated = true;
			}
			else
			{
				continue;
			}
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
			isUpdated = true;
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
		isUpdated = true;
	}

	Socket acceptedSocket;

	MpnwResult mpnwResult = acceptSocket(
		serverSocket,
		&acceptedSocket);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		server->sessionCount = sessionCount;
		return isUpdated;
	}

	if (sessionCount < sessionBufferSize)
	{
		void* session;

		bool result = onCreate(
			server,
			acceptedSocket,
			&session);

		if (result == true)
		{
			struct StreamSession streamSession;
			streamSession.receiveSocket = acceptedSocket;
			streamSession.handle = session;
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

	server->sessionCount = sessionCount;
	return true;
}

bool streamSessionSend(
	StreamSession session,
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
