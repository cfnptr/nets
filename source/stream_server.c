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

void destroyStreamServer(StreamServer streamServer)
{
	assert(isNetworkInitialized() == true);

	if (streamServer == NULL)
		return;

	StreamSession sessionBuffer = streamServer->sessionBuffer;
	size_t sessionCount = streamServer->sessionCount;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = &sessionBuffer[i];
		Socket receiveSocket = streamSession->receiveSocket;

		onDestroy(
			streamServer,
			streamSession);
		shutdownSocket(
			receiveSocket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	}

	shutdownSocket(
		streamServer->acceptSocket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(streamServer->acceptSocket);
	free(streamServer->receiveBuffer);
	free(sessionBuffer);
	free(streamServer);
}

size_t getStreamServerSessionBufferSize(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->sessionBufferSize;
}

size_t getStreamServerReceiveBufferSize(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->receiveBufferSize;
}

OnStreamSessionCreate getStreamServerOnCreate(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->onCreate;
}

OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->onDestroy;
}

OnStreamSessionUpdate getStreamServerOnUpdate(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->onUpdate;
}

OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->onReceive;
}

void* getStreamServerHandle(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->handle;
}

Socket getStreamServerSocket(StreamServer streamServer)
{
	assert(streamServer != NULL);
	assert(isNetworkInitialized() == true);
	return streamServer->acceptSocket;
}

Socket getStreamSessionSocket(StreamSession streamSession)
{
	assert(streamSession != NULL);
	assert(isNetworkInitialized() == true);
	return streamSession->receiveSocket;
}

void* getStreamSessionHandle(StreamSession streamSession)
{
	assert(streamSession != NULL);
	assert(isNetworkInitialized() == true);
	return streamSession->handle;
}

bool updateStreamServer(StreamServer streamServer)
{
	assert(streamServer != NULL);

	bool isUpdated = false;

	StreamSession sessionBuffer = streamServer->sessionBuffer;
	size_t sessionBufferSize = streamServer->sessionBufferSize;
	size_t sessionCount = streamServer->sessionCount;
	uint8_t* receiveBuffer = streamServer->receiveBuffer;
	size_t receiveBufferSize = streamServer->receiveBufferSize;
	OnStreamSessionCreate onCreate = streamServer->onCreate;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;
	OnStreamSessionUpdate onUpdate = streamServer->onUpdate;
	OnStreamSessionReceive onReceive = streamServer->onReceive;
	Socket serverSocket = streamServer->acceptSocket;
	bool isServerSocketSsl = getSocketSslContext(serverSocket) != NULL;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = &sessionBuffer[i];
		Socket receiveSocket = streamSession->receiveSocket;

		if (streamSession->isSslAccepted == false)
		{
			bool result = acceptSslSocket(receiveSocket);

			if (result == true)
			{
				streamSession->isSslAccepted = true;
				isUpdated = true;
			}
			else
			{
				continue;
			}
		}

		bool result = onUpdate(
			streamServer,
			streamSession);

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
			streamServer,
			streamSession,
			receiveBuffer,
			byteCount);

		if (result == true)
		{
			isUpdated = true;
			continue;
		}

	DESTROY_SESSION:
		onDestroy(
			streamServer,
			streamSession);
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
		streamServer->sessionCount = sessionCount;
		return isUpdated;
	}

	if (sessionCount < sessionBufferSize)
	{
		void* session;

		bool result = onCreate(
			streamServer,
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

	streamServer->sessionCount = sessionCount;
	return true;
}

bool streamSessionSend(
	StreamSession streamSession,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(streamSession != NULL);
	assert(sendBuffer != NULL);
	assert(byteCount != 0);
	assert(isNetworkInitialized() == true);

	return socketSend(
		streamSession->receiveSocket,
		sendBuffer,
		byteCount);
}
