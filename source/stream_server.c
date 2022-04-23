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
#include "mpmt/common.h"

struct StreamSession_T
{
	Socket receiveSocket;
	SocketAddress socketAddress;
	void* handle;
	double lastUpdateTime;
};
struct StreamServer_T
{
	size_t sessionBufferSize;
	size_t dataBufferSize;
	double timeoutTime;
	OnStreamSessionCreate onCreate;
	OnStreamSessionDestroy onDestroy;
	OnStreamSessionReceive onReceive;
	void* handle;
	uint8_t* dataBuffer;
	StreamSession* sessionBuffer;
	size_t sessionCount;
	Socket acceptSocket;
};

MpnwResult createStreamServer(
	AddressFamily addressFamily,
	const char* service,
	size_t sessionBufferSize,
	size_t connectionQueueSize,
	size_t dataBufferSize,
	double timeoutTime,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamServer* streamServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(service);
	assert(sessionBufferSize > 0);
	assert(connectionQueueSize > 0);
	assert(dataBufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(onCreate);
	assert(onDestroy);
	assert(onReceive);
	assert(streamServer);

	StreamServer streamServerInstance = malloc(
		sizeof(StreamServer_T));

	if (!streamServerInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	streamServerInstance->timeoutTime = timeoutTime;
	streamServerInstance->onCreate = onCreate;
	streamServerInstance->onDestroy = onDestroy;
	streamServerInstance->onReceive = onReceive;
	streamServerInstance->handle = handle;

	uint8_t* dataBuffer = malloc(
		dataBufferSize * sizeof(uint8_t));

	if (!dataBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	streamServerInstance->dataBuffer = dataBuffer;
	streamServerInstance->dataBufferSize = dataBufferSize;

	StreamSession* sessionBuffer = malloc(
		sessionBufferSize * sizeof(StreamSession));

	if (!sessionBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	streamServerInstance->sessionBufferSize = sessionBufferSize;
	streamServerInstance->sessionBuffer = sessionBuffer;
	streamServerInstance->sessionCount = 0;

	SocketAddress socketAddress;

	MpnwResult mpnwResult = createAnySocketAddress(
		addressFamily,
		&socketAddress);

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

	mpnwResult = listenSocket(
		acceptSocket,
		connectionQueueSize);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return mpnwResult;
	}

	*streamServer = streamServerInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyStreamServer(StreamServer streamServer)
{
	if (!streamServer)
		return;

	StreamSession* sessionBuffer = streamServer->sessionBuffer;
	size_t sessionCount = streamServer->sessionCount;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = sessionBuffer[i];
		Socket receiveSocket = streamSession->receiveSocket;
		onDestroy(streamServer, streamSession, SUCCESS_MPNW_RESULT);
		destroySocketAddress(streamSession->socketAddress);
		shutdownSocket(receiveSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
		free(streamSession);
	}

	Socket socket = streamServer->acceptSocket;

	if (socket)
	{
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	free(streamServer->dataBuffer);
	free(sessionBuffer);
	free(streamServer);
}

size_t getStreamServerSessionBufferSize(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->sessionBufferSize;
}
size_t getStreamServerDataBufferSize(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->dataBufferSize;
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
OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onReceive;
}
double getStreamServerTimeoutTime(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->timeoutTime;
}
void* getStreamServerHandle(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->handle;
}
uint8_t* getStreamServerDataBuffer(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->dataBuffer;
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
SocketAddress getStreamSessionAddress(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->socketAddress;
}
void* getStreamSessionHandle(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->handle;
}

inline static void destroyStreamSession(StreamSession streamSession)
{
	if (!streamSession)
		return;

	Socket receiveSocket = streamSession->receiveSocket;

	if (receiveSocket)
	{
		shutdownSocket(receiveSocket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	}

	destroySocketAddress(streamSession->socketAddress);
	free(streamSession);
}
bool updateStreamServer(StreamServer streamServer)
{
	assert(streamServer);
	StreamSession* sessionBuffer = streamServer->sessionBuffer;
	size_t sessionBufferSize = streamServer->sessionBufferSize;
	size_t sessionCount = streamServer->sessionCount;
	uint8_t* dataBuffer = streamServer->dataBuffer;
	size_t dataBufferSize = streamServer->dataBufferSize;
	double timeoutTime = streamServer->timeoutTime;
	OnStreamSessionCreate onCreate = streamServer->onCreate;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;
	OnStreamSessionReceive onReceive = streamServer->onReceive;
	Socket serverSocket = streamServer->acceptSocket;
	bool isServerSocketSsl = getSocketSslContext(serverSocket) != NULL;
	double currentTime = getCurrentClock();

	bool isUpdated = false;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = sessionBuffer[i];
		Socket receiveSocket = streamSession->receiveSocket;
		double lastUpdateTime = streamSession->lastUpdateTime;

		MpnwResult mpnwResult;

		if (lastUpdateTime < 0.0)
		{
			if (lastUpdateTime + currentTime > timeoutTime)
			{
				mpnwResult = TIMED_OUT_MPNW_RESULT;
				goto DESTROY_SESSION;
			}

			mpnwResult = acceptSslSocket(receiveSocket);

			if (mpnwResult == IN_PROGRESS_MPNW_RESULT)
				continue;
			if (mpnwResult != SUCCESS_MPNW_RESULT)
				goto DESTROY_SESSION;

			streamSession->lastUpdateTime = -currentTime;
			isUpdated = true;
		}

		if (currentTime - lastUpdateTime > timeoutTime)
		{
			mpnwResult = TIMED_OUT_MPNW_RESULT;
			goto DESTROY_SESSION;
		}

		size_t byteCount;

		mpnwResult = socketReceive(
			receiveSocket,
			dataBuffer,
			dataBufferSize,
			&byteCount);

		if (mpnwResult == IN_PROGRESS_MPNW_RESULT)
			continue;
		if (mpnwResult != SUCCESS_MPNW_RESULT)
			goto DESTROY_SESSION;

		bool result = onReceive(
			streamServer,
			streamSession,
			dataBuffer,
			byteCount);

		if (!result)
			goto DESTROY_SESSION;

		streamSession->lastUpdateTime = currentTime;
		isUpdated = true;
		continue;

	DESTROY_SESSION:
		onDestroy(streamServer, streamSession, mpnwResult);
		destroyStreamSession(streamSession);

		for (size_t j = i + 1; j < sessionCount; j++)
			sessionBuffer[j - 1] = sessionBuffer[j];

		if (i > 0) i--;
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

		isUpdated = true;

		StreamSession streamSession = calloc(
			1, sizeof(StreamSession_T));

		if (!streamSession)
			continue;

		streamSession->receiveSocket = acceptedSocket;

		SocketAddress socketAddress;

		mpnwResult = createAnySocketAddress(
			IP_V6_ADDRESS_FAMILY,
			&socketAddress);

		if (mpnwResult != SUCCESS_MPNW_RESULT)
		{
			destroyStreamSession(streamSession);
			continue;
		}

		streamSession->socketAddress = socketAddress;

		bool result = getSocketRemoteAddress(
			acceptedSocket,
			socketAddress);

		if (!result)
		{
			destroyStreamSession(streamSession);
			continue;
		}

		void* session;

		result = onCreate(
			streamServer,
			acceptedSocket,
			socketAddress,
			&session);

		if (!result)
		{
			destroyStreamSession(streamSession);
			continue;
		}

		streamSession->lastUpdateTime =
			isServerSocketSsl ? -currentTime : currentTime;
		streamSession->handle = session;
		sessionBuffer[sessionCount++] = streamSession;
	}
}

MpnwResult streamSessionSend(
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
MpnwResult streamSessionSendMessage(
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
