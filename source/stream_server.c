// Copyright 2020-2022 Nikita Fediuchin. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "mpnw/stream_server.h"

struct StreamSession_T
{
	Socket receiveSocket;
	void* handle;
	uint8_t isSslAccepted;
	uint8_t _alignment[7];
};
struct StreamServer_T
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
	size_t connectionQueueSize,
	size_t receiveBufferSize,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionUpdate onUpdate,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamServer* streamServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(service);
	assert(sessionBufferSize > 0);
	assert(connectionQueueSize > 0);
	assert(receiveBufferSize > 0);
	assert(onCreate);
	assert(onDestroy);
	assert(onUpdate);
	assert(onReceive);
	assert(streamServer);

	StreamServer streamServerInstance = malloc(
		sizeof(StreamServer_T));

	if (!streamServerInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	streamServerInstance->onCreate = onCreate;
	streamServerInstance->onDestroy = onDestroy;
	streamServerInstance->onUpdate = onUpdate;
	streamServerInstance->onReceive = onReceive;
	streamServerInstance->handle = handle;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (!receiveBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	streamServerInstance->receiveBufferSize = receiveBufferSize;
	streamServerInstance->receiveBuffer = receiveBuffer;

	StreamSession sessionBuffer = malloc(
		sessionBufferSize * sizeof(StreamSession_T));

	if (!sessionBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	streamServerInstance->sessionBufferSize = sessionBufferSize;
	streamServerInstance->sessionBuffer = sessionBuffer;
	streamServerInstance->sessionCount = 0;

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service,
			&socketAddress);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service,
			&socketAddress);
	}
	else
	{
		abort();
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return mpnwResult;
	}

	Socket acceptSocket;

	mpnwResult = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		sslContext,
		&acceptSocket);

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return mpnwResult;
	}

	streamServerInstance->acceptSocket = acceptSocket;

	if (!listenSocket(acceptSocket, connectionQueueSize))
	{
		destroyStreamServer(streamServerInstance);
		return FAILED_TO_LISTEN_SOCKET_MPNW_RESULT;
	}

	*streamServer = streamServerInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyStreamServer(StreamServer streamServer)
{
	if (!streamServer)
		return;

	StreamSession sessionBuffer = streamServer->sessionBuffer;
	size_t sessionCount = streamServer->sessionCount;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = &sessionBuffer[i];
		Socket receiveSocket = streamSession->receiveSocket;

		onDestroy(streamServer, streamSession);
		shutdownSocket(receiveSocket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	}

	Socket socket = streamServer->acceptSocket;

	if (socket)
	{
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	free(streamServer->receiveBuffer);
	free(sessionBuffer);
	free(streamServer);
}

size_t getStreamServerSessionBufferSize(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->sessionBufferSize;
}
size_t getStreamServerReceiveBufferSize(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->receiveBufferSize;
}
OnStreamSessionCreate getStreamServerOnCreate(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onCreate;
}
OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onDestroy;
}
OnStreamSessionUpdate getStreamServerOnUpdate(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onUpdate;
}
OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onReceive;
}
void* getStreamServerHandle(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->handle;
}
Socket getStreamServerSocket(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->acceptSocket;
}
Socket getStreamSessionSocket(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->receiveSocket;
}
void* getStreamSessionHandle(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->handle;
}

bool updateStreamServer(StreamServer streamServer)
{
	assert(streamServer);

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

		if (!onUpdate(streamServer, streamSession))
			goto DESTROY_SESSION;

		Socket receiveSocket = streamSession->receiveSocket;

		if (!streamSession->isSslAccepted)
		{
			if (!acceptSslSocket(receiveSocket))
				continue;

			streamSession->isSslAccepted = true;
			isUpdated = true;
		}

		size_t byteCount;

		bool result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (!result)
			continue;

		result = onReceive(
			streamServer,
			streamSession,
			receiveBuffer,
			byteCount);

		if (result)
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

	while (true)
	{
		if (sessionCount == sessionBufferSize)
		{
			streamServer->sessionCount = sessionCount;
			return isUpdated;
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

		void* session;

		bool result = onCreate(
			streamServer,
			acceptedSocket,
			&session);

		if (result)
		{
			StreamSession_T streamSession;
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
}

bool streamSessionSend(
	StreamSession streamSession,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(streamSession);
	assert(sendBuffer);
	assert(byteCount > 0);

	return socketSend(
		streamSession->receiveSocket,
		sendBuffer,
		byteCount);
}
bool streamSessionSendMessage(
	StreamSession streamSession,
	StreamMessage streamMessage)
{
	assert(streamSession);
	assert(streamMessage.buffer);
	assert(streamMessage.size > 0);
	assert(streamMessage.size == streamMessage.offset);

	return socketSend(
		streamSession->receiveSocket,
		streamMessage.buffer,
		streamMessage.size);
}
