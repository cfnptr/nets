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

struct StreamClient_T
{
	size_t receiveBufferSize;
	OnStreamClientReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	Socket socket;
};

MpnwResult createStreamClient(
	AddressFamily addressFamily,
	size_t receiveBufferSize,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* streamClient)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(receiveBufferSize > 0);
	assert(onReceive);
	assert(streamClient);

	StreamClient streamClientInstance = malloc(
		sizeof(StreamClient_T));

	if (!streamClientInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (!receiveBuffer)
	{
		free(streamClientInstance);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_SERVICE,
			&socketAddress);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_SERVICE,
			&socketAddress);
	}
	else
	{
		abort();
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(streamClientInstance);
		return mpnwResult;
	}

	Socket socket;

	mpnwResult = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		sslContext,
		&socket);

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(streamClientInstance);
		return mpnwResult;
	}

	streamClientInstance->receiveBufferSize = receiveBufferSize;
	streamClientInstance->onReceive = onReceive;
	streamClientInstance->handle = handle;
	streamClientInstance->receiveBuffer = receiveBuffer;
	streamClientInstance->socket = socket;

	*streamClient = streamClientInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyStreamClient(StreamClient streamClient)
{
	if (!streamClient)
		return;

	shutdownSocket(streamClient->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(streamClient->socket);
	free(streamClient->receiveBuffer);
	free(streamClient);
}

size_t getStreamClientReceiveBufferSize(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->receiveBufferSize;
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
Socket getStreamClientSocket(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->socket;
}

bool connectStreamClient(
	StreamClient streamClient,
	SocketAddress remoteAddress,
	double timeoutTime)
{
	assert(streamClient);
	assert(remoteAddress);
	assert(timeoutTime >= 0.0);

	Socket socket = streamClient->socket;
	double timeout = getCurrentClock() + timeoutTime;

	while (getCurrentClock() < timeout)
	{
		if (connectSocket(socket, remoteAddress))
			goto CONNECT_SSL;

		sleepThread(0.001);
	}

	return false;

CONNECT_SSL:

	if (!getSocketSslContext(socket))
		return true;

	while (getCurrentClock() < timeout)
	{
		if (connectSslSocket(socket))
			return true;

		sleepThread(0.001);
	}

	return false;
}

bool updateStreamClient(StreamClient streamClient)
{
	assert(streamClient);

	uint8_t* receiveBuffer =
		streamClient->receiveBuffer;

	size_t byteCount;

	bool result = socketReceive(
		streamClient->socket,
		receiveBuffer,
		streamClient->receiveBufferSize,
		&byteCount);

	if (!result)
		return false;

	streamClient->onReceive(
		streamClient,
		receiveBuffer,
		byteCount);
	return true;
}

bool streamClientSend(
	StreamClient streamClient,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(streamClient);
	assert(sendBuffer);
	assert(byteCount > 0);

	return socketSend(
		streamClient->socket,
		sendBuffer,
		byteCount);
}

bool streamClientSendMessage(
	StreamClient streamClient,
	StreamMessage streamMessage)
{
	assert(streamClient);
	assert(streamMessage.buffer);
	assert(streamMessage.size > 0);
	assert(streamMessage.size == streamMessage.offset);

	return socketSend(
		streamClient->socket,
		streamMessage.buffer,
		streamMessage.size);
}
