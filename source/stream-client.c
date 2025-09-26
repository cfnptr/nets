// Copyright 2020-2025 Nikita Fediuchin. All rights reserved.
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

#include "nets/stream-client.h"
#include "mpmt/thread.h"
#include "mpio/os.h"

struct StreamClient_T
{
	size_t bufferSize;
	double timeoutTime;
	OnStreamClientReceive onReceive;
	void* handle;
	SslContext sslContext;
	uint8_t* buffer;
	Socket socket;
	double timeout;
};

//**********************************************************************************************************************
NetsResult createStreamClient(size_t bufferSize, double timeoutTime, OnStreamClientReceive onReceive,
	void* handle, SslContext sslContext, StreamClient* streamClient)
{
	assert(bufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(onReceive);
	assert(streamClient);

	StreamClient streamClientInstance = calloc(1, sizeof(StreamClient_T));
	if (!streamClientInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	streamClientInstance->timeoutTime = timeoutTime;
	streamClientInstance->onReceive = onReceive;
	streamClientInstance->handle = handle;
	streamClientInstance->sslContext = sslContext;
	streamClientInstance->socket = NULL;
	streamClientInstance->timeout = 0.0;

	uint8_t* buffer = malloc(bufferSize * sizeof(uint8_t));
	if (!buffer)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	streamClientInstance->buffer = buffer;
	streamClientInstance->bufferSize = bufferSize;
	*streamClient = streamClientInstance;
	return SUCCESS_NETS_RESULT;
}
void destroyStreamClient(StreamClient streamClient)
{
	if (!streamClient)
		return;

	if (streamClient->socket)
	{
		Socket socket = streamClient->socket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	free(streamClient->buffer);
	free(streamClient);
}

//**********************************************************************************************************************
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

double getStreamClientTimeoutTime(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->timeoutTime;
}
void setStreamClientTimeoutTime(StreamClient streamClient, double timeoutTime)
{
	assert(streamClient);
	assert(timeoutTime > 0.0);
	streamClient->timeoutTime = timeoutTime;
}

SslContext getStreamClientSslContext(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->sslContext;
}
void setStreamClientSslContext(StreamClient streamClient, SslContext sslContext)
{
	assert(streamClient);
	assert(!streamClient->socket);
	streamClient->sslContext = sslContext;
}

//**********************************************************************************************************************
bool isStreamClientConnected(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->socket;
}
NetsResult connectAddressStreamClient(StreamClient streamClient, SocketAddress remoteAddress, const char* hostname)
{
	assert(streamClient);
	assert(remoteAddress);
	assert(!streamClient->socket);
	SocketFamily socketFamily = getSocketAddressFamily(remoteAddress);

	SocketAddress socketAddress;
	NetsResult netsResult = createAnySocketAddress(socketFamily, &socketAddress);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	Socket socket;
	netsResult = createSocket(STREAM_SOCKET_TYPE, socketFamily,
		socketAddress, false, false, streamClient->sslContext, &socket);
	destroySocketAddress(socketAddress);

	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	double timeout = getCurrentClock() + streamClient->timeoutTime;

	while (getCurrentClock() < timeout)
	{
		netsResult = connectSocket(socket, remoteAddress);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
		{
			sleepThread(0.001);
			continue;
		}
		if (netsResult != SUCCESS_NETS_RESULT && netsResult != ALREADY_CONNECTED_NETS_RESULT)
		{
			destroySocket(socket);
			return netsResult;
		}
		goto CONNECT_SSL;
	}

	destroySocket(socket);
	return TIMED_OUT_NETS_RESULT;

CONNECT_SSL:

	if (!getSocketSslContext(socket))
	{
		assert(hostname == NULL);
		streamClient->socket = socket;
		streamClient->timeout = timeout;
		return SUCCESS_NETS_RESULT;
	}

	while (getCurrentClock() < timeout)
	{
		netsResult = connectSslSocket(socket, hostname);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
		{
			sleepThread(0.001);
			continue;
		}
		if (netsResult != SUCCESS_NETS_RESULT)
		{
			destroySocket(socket);
			return netsResult;
		}

		streamClient->socket = socket;
		streamClient->timeout = timeout;
		return SUCCESS_NETS_RESULT;
	}

	destroySocket(socket);
	return TIMED_OUT_NETS_RESULT;
}

//**********************************************************************************************************************
inline static NetsResult connectByHostname(StreamClient streamClient, 
	const char* hostname, const char* service, bool setSNI, SocketFamily socketFamily)
{
	assert(streamClient);
	assert(hostname);
	assert(service);
	assert(!streamClient->socket);
	assert(socketFamily < SOCKET_FAMILY_COUNT);

	SocketAddress* resolvedAddresses; size_t resolvedAddressCount;
	NetsResult netsResult = resolveSocketAddresses(hostname, service,
		socketFamily, STREAM_SOCKET_TYPE, &resolvedAddresses, &resolvedAddressCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	SocketAddress socketAddress;
	netsResult = createAnySocketAddress(socketFamily, &socketAddress);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
		return netsResult;
	}

	double timeout = getCurrentClock() + streamClient->timeoutTime;

	for (size_t i = 0; i < resolvedAddressCount; i++)
	{
		Socket socket;
		netsResult = createSocket(STREAM_SOCKET_TYPE, socketFamily, 
			socketAddress, false, false, streamClient->sslContext, &socket);
		if (netsResult != SUCCESS_NETS_RESULT)
		{
			destroySocketAddress(socketAddress);
			destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
			return netsResult;
		}

		SocketAddress remoteAddress = resolvedAddresses[i];

		while (getCurrentClock() < timeout)
		{
			netsResult = connectSocket(socket, remoteAddress);
			if (netsResult == IN_PROGRESS_NETS_RESULT)
			{
				sleepThread(0.001);
				continue;
			}
			if (netsResult != SUCCESS_NETS_RESULT && netsResult != ALREADY_CONNECTED_NETS_RESULT)
			{
				destroySocket(socket);
				goto CONTINUE;
			}
			goto CONNECT_SSL;
		}

		destroySocket(socket);
		destroySocketAddress(socketAddress);
		destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
		return TIMED_OUT_NETS_RESULT;

CONNECT_SSL:

		if (!getSocketSslContext(socket))
		{
			assert(setSNI == false);
			destroySocketAddress(socketAddress);
			destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
			streamClient->socket = socket;
			streamClient->timeout = timeout;
			return SUCCESS_NETS_RESULT;
		}

		while (getCurrentClock() < timeout)
		{
			netsResult = connectSslSocket(socket, setSNI ? hostname : NULL);
			if (netsResult == IN_PROGRESS_NETS_RESULT)
			{
				sleepThread(0.001);
				continue;
			}
			if (netsResult != SUCCESS_NETS_RESULT)
			{
				destroySocket(socket);
				goto CONTINUE;
			}

			destroySocketAddress(socketAddress);
			destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
			streamClient->socket = socket;
			streamClient->timeout = timeout;
			return SUCCESS_NETS_RESULT;
		}

		destroySocket(socket);
		destroySocketAddress(socketAddress);
		destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
		return TIMED_OUT_NETS_RESULT;
CONTINUE:
		continue;
	}

	destroySocketAddress(socketAddress);
	return netsResult;
}

//**********************************************************************************************************************
NetsResult connectHostnameStreamClient(StreamClient streamClient, const char* hostname, const char* service, bool setSNI)
{
	assert(streamClient);
	assert(hostname);
	assert(service);
	assert(!streamClient->socket);

	NetsResult netsResult = connectByHostname(streamClient, hostname, service, setSNI, IP_V4_SOCKET_FAMILY);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		NetsResult netsResult6 = connectByHostname(streamClient, hostname, service, setSNI, IP_V6_SOCKET_FAMILY);
		if (netsResult6 != SUCCESS_NETS_RESULT)
			return netsResult;
	}
	return SUCCESS_NETS_RESULT;
}
void disconnectStreamClient(StreamClient streamClient)
{
	assert(streamClient);

	if (streamClient->socket)
	{
		Socket socket = streamClient->socket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
		streamClient->socket = NULL;
		streamClient->timeout = 0.0;
	}
}

NetsResult updateStreamClient(StreamClient streamClient)
{
	assert(streamClient);
	assert(streamClient->socket);

	double currentTime = getCurrentClock();
	if (currentTime > streamClient->timeout)
		return TIMED_OUT_NETS_RESULT;

	uint8_t* receiveBuffer = streamClient->buffer;

	size_t byteCount;
	NetsResult netsResult = socketReceive(streamClient->socket,
		receiveBuffer, streamClient->bufferSize, &byteCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	streamClient->timeout = currentTime + streamClient->timeoutTime;
	streamClient->onReceive(streamClient, receiveBuffer, byteCount);
	return SUCCESS_NETS_RESULT;
}
void resetStreamClientTimeout(StreamClient streamClient)
{
	assert(streamClient);
	streamClient->timeout = getCurrentClock() + streamClient->timeoutTime;
}

//**********************************************************************************************************************
NetsResult streamClientSend(StreamClient streamClient, const void* sendBuffer, size_t byteCount)
{
	assert(streamClient);
	NetsResult netsResult = socketSend(streamClient->socket, sendBuffer, byteCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;
	return SUCCESS_NETS_RESULT;
}
NetsResult streamClientSendMessage(StreamClient streamClient, StreamMessage streamMessage)
{
	assert(streamClient);
	assert(streamMessage.buffer);
	assert(streamMessage.size > 0);
	assert(streamMessage.size == streamMessage.offset);

	NetsResult netsResult = socketSend(streamClient->socket, streamMessage.buffer, streamMessage.size);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;
	return SUCCESS_NETS_RESULT;
}