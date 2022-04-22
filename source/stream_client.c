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

#include "mpnw/stream_client.h"

#include "mpmt/thread.h"
#include "mpmt/common.h"

struct StreamClient_T
{
	size_t bufferSize;
	double timeoutTime;
	OnStreamClientReceive onReceive;
	void* handle;
	SslContext sslContext;
	uint8_t* buffer;
	Socket socket;
};

MpnwResult createStreamClient(
	size_t bufferSize,
	double timeoutTime,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* streamClient)
{
	assert(bufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(onReceive);
	assert(streamClient);

	StreamClient streamClientInstance = malloc(
		sizeof(StreamClient_T));

	if (!streamClientInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	streamClientInstance->timeoutTime = timeoutTime;
	streamClientInstance->onReceive = onReceive;
	streamClientInstance->handle = handle;
	streamClientInstance->sslContext = sslContext;
	streamClientInstance->socket = NULL;

	uint8_t* buffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (!buffer)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	streamClientInstance->buffer = buffer;
	streamClientInstance->bufferSize = bufferSize;

	*streamClient = streamClientInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyStreamClient(StreamClient streamClient)
{
	if (!streamClient)
		return;

	Socket socket = streamClient->socket;

	if (socket)
	{
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	free(streamClient->buffer);
	free(streamClient);
}

size_t getStreamClientBufferSize(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->bufferSize;
}
OnStreamClientReceive getStreamClientOnReceive(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->onReceive;
}
void* getStreamClientHandle(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->handle;
}
uint8_t* getStreamClientBuffer(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->buffer;
}
Socket getStreamClientSocket(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->socket;
}

double getStreamClientTimeoutTime(
	StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->timeoutTime;
}
void setStreamClientTimeoutTime(
	StreamClient streamClient,
	double timeoutTime)
{
	assert(streamClient);
	assert(timeoutTime > 0.0);
	streamClient->timeoutTime = timeoutTime;
}

SslContext getStreamClientSslContext(
	StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->sslContext;
}
void setStreamClientSslContext(
	StreamClient streamClient,
	SslContext sslContext)
{
	assert(streamClient);
	assert(!streamClient->socket);
	streamClient->sslContext = sslContext;
}

bool isStreamClientConnected(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->socket;
}
MpnwResult connectStreamClient(
	StreamClient streamClient,
	SocketAddress remoteAddress,
	const char* hostname)
{
	assert(streamClient);
	assert(remoteAddress);
	assert(!streamClient->socket);

	AddressFamily addressFamily = getSocketAddressFamily(
		remoteAddress);

	SocketAddress socketAddress;

	MpnwResult mpnwResult = createAnySocketAddress(
		addressFamily,
		&socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	Socket socket;

	mpnwResult = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		streamClient->sslContext,
		&socket);

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	streamClient->socket = socket;

	double timeout = getCurrentClock() +
		streamClient->timeoutTime;

	while (getCurrentClock() < timeout)
	{
		mpnwResult = connectSocket(socket, remoteAddress);

		if (mpnwResult == IN_PROGRESS_MPNW_RESULT)
		{
			sleepThread(0.001);
			continue;
		}

		goto CONNECT_SSL;
	}

	return TIMED_OUT_MPNW_RESULT;

CONNECT_SSL:

	if (!getSocketSslContext(socket))
	{
		assert(hostname == NULL);
		streamClient->socket = socket;
		return SUCCESS_MPNW_RESULT;
	}

	while (getCurrentClock() < timeout)
	{
		mpnwResult = connectSslSocket(socket, hostname);

		if (mpnwResult == IN_PROGRESS_MPNW_RESULT)
		{
			sleepThread(0.001);
			continue;
		}

		streamClient->socket = socket;
		return SUCCESS_MPNW_RESULT;
	}

	return TIMED_OUT_MPNW_RESULT;
}
void disconnectStreamClient(StreamClient streamClient)
{
	assert(streamClient);

	Socket socket = streamClient->socket;

	if (socket)
	{
		shutdownSocket(socket,
			RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
		streamClient->socket = NULL;
	}
}

MpnwResult updateStreamClient(StreamClient streamClient)
{
	assert(streamClient);
	assert(streamClient->socket);

	uint8_t* receiveBuffer = streamClient->buffer;
	size_t byteCount;

	MpnwResult mpnwResult = socketReceive(
		streamClient->socket,
		receiveBuffer,
		streamClient->bufferSize,
		&byteCount);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	streamClient->onReceive(
		streamClient,
		receiveBuffer,
		byteCount);
	return SUCCESS_MPNW_RESULT;
}

MpnwResult streamClientSend(
	StreamClient streamClient,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(streamClient);
	assert(sendBuffer);
	assert(byteCount > 0);
	assert(streamClient->socket);

	return socketSend(
		streamClient->socket,
		sendBuffer,
		byteCount);
}

MpnwResult streamClientSendMessage(
	StreamClient streamClient,
	StreamMessage streamMessage)
{
	assert(streamClient);
	assert(streamMessage.buffer);
	assert(streamMessage.size > 0);
	assert(streamMessage.size == streamMessage.offset);
	assert(streamClient->socket);

	return socketSend(
		streamClient->socket,
		streamMessage.buffer,
		streamMessage.size);
}
