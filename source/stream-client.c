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
#include <string.h>

#if __linux__
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#elif __APPLE__
#include <fcntl.h>
#include <unistd.h>
#include <sys/event.h>
#endif

struct StreamClient_T
{
	double timeoutTime;
	OnStreamClientConnection onConnection;
	OnStreamClientReceive onReceive;
	void* handle;
	SslContext sslContext;
	uint8_t* buffer;
	size_t bufferSize;
	Socket socket;
	double lastReceiveTime;
	Thread receiveThread;
	#if __linux__ || __APPLE__
	int eventPool;
	#endif
	#if __linux__
	int wakeupEvent;
	#endif
	volatile bool isRunning;
	volatile bool isConnected;
};

typedef struct ConnectByAddress_T
{
	StreamClient streamClient;
	bool isByAddress;
	bool noDelay;
	char* hostname;
	SocketAddress remoteAddress;
} ConnectByAddress;
typedef struct ConnectByHostname_T
{
	StreamClient streamClient;
	bool isByAddress;
	bool noDelay;
	bool setSNI;
	char* hostname;
	char* service;
} ConnectByHostname;
typedef union StreamClientConnect_T
{
	ConnectByAddress byAddress;
	ConnectByHostname byHostname;
} StreamClientConnect;

inline static void destroyStreamClientConnect(StreamClientConnect* connectData)
{
	if (connectData->byAddress.isByAddress)
	{
		free(connectData->byAddress.hostname);
		destroySocketAddress(connectData->byAddress.remoteAddress);
	}
	else
	{
		free(connectData->byHostname.hostname);
		free(connectData->byHostname.service);
	}
	free(connectData);
}

//**********************************************************************************************************************
inline static NetsResult connectSslStreamClient(const char* hostname, Socket socket, double nextTimeout)
{
	if (!getSocketSslContext(socket))
		return SUCCESS_NETS_RESULT;

	while (getCurrentClock() < nextTimeout)
	{
		NetsResult netsResult = connectSslSocket(socket, hostname);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
		{
			sleepThread(0.001);
			continue;
		}

		if (netsResult != SUCCESS_NETS_RESULT)
			return netsResult;
		return SUCCESS_NETS_RESULT;
	}

	return TIMED_OUT_NETS_RESULT;
}
inline static NetsResult connectStreamClientAddress(StreamClient streamClient, 
	SocketAddress remoteAddress, const char* hostname, bool noDelay, SocketFamily socketFamily)
{
	SocketAddress socketAddress;
	NetsResult netsResult = createAnySocketAddress(socketFamily, &socketAddress);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	Socket socket;
	netsResult = createSocket(STREAM_SOCKET_TYPE, socketFamily,
		socketAddress, false, false, streamClient->sslContext, &socket);
	destroySocketAddress(socketAddress);

	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroySocket(socket);
		return netsResult;
	}
	setSocketNoDelay(socket, noDelay);

	double nextTimeout = getCurrentClock() + streamClient->timeoutTime;

	while (getCurrentClock() < nextTimeout)
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

		netsResult = connectSslStreamClient(hostname, socket, nextTimeout);
		if (netsResult != SUCCESS_NETS_RESULT)
		{
			destroySocket(socket);
			return netsResult;
		}

		streamClient->socket = socket;
		streamClient->lastReceiveTime = getCurrentClock(); // Note: getting latest time here.
		return SUCCESS_NETS_RESULT;
	}

	return TIMED_OUT_NETS_RESULT;
}
inline static NetsResult connectStreamClientHostname(StreamClient streamClient, 
	const char* hostname, const char* service, bool noDelay, bool setSNI, SocketFamily socketFamily)
{
	SocketAddress* resolvedAddresses; size_t resolvedAddressCount;
	NetsResult netsResult = resolveSocketAddresses(hostname, service,
		socketFamily, STREAM_SOCKET_TYPE, &resolvedAddresses, &resolvedAddressCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	const char* sni = setSNI ? hostname : NULL;

	for (size_t i = 0; i < resolvedAddressCount; i++)
	{
		netsResult = connectStreamClientAddress(streamClient, resolvedAddresses[i], sni, noDelay, socketFamily);
		if (netsResult == SUCCESS_NETS_RESULT)
			break;
	}

	destroySocketAddresses(resolvedAddresses, resolvedAddressCount);
	return netsResult;
}

//**********************************************************************************************************************
inline static void processStreamClient(StreamClient streamClient)
{
	if (getCurrentClock() - streamClient->lastReceiveTime > streamClient->timeoutTime)
	{
		streamClient->isRunning = streamClient->isConnected = false;
		return;
	}

	OnStreamClientReceive onReceive = streamClient->onReceive;
	Socket socket = streamClient->socket;
	uint8_t* buffer = streamClient->buffer;
	size_t bufferSize = streamClient->bufferSize;

	size_t byteCount;
	while (streamClient->isRunning)
	{
		NetsResult netsResult = socketReceive(socket, buffer, bufferSize, &byteCount);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
		{
			streamClient->lastReceiveTime = getCurrentClock(); // Note: getting latest time here.
			return;
		}

		if (netsResult != SUCCESS_NETS_RESULT || byteCount == 0 ||
			!onReceive(streamClient, buffer, byteCount))
		{
			streamClient->isRunning = streamClient->isConnected = false;
			return;
		}
	}
}

inline static void streamClientReceive(void* argument)
{
	setThreadName("RECV");
	setThreadForegroundPriority();

	#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_IGN);
	#endif

	StreamClientConnect* connectData = (StreamClientConnect*)argument;
	StreamClient streamClient = connectData->byAddress.streamClient;

	NetsResult netsResult;
	if (connectData->byAddress.isByAddress)
	{
		SocketFamily socketFamily = getSocketAddressFamily(connectData->byAddress.remoteAddress);
		netsResult = connectStreamClientAddress(streamClient, connectData->byAddress.remoteAddress, 
			connectData->byAddress.hostname, connectData->byAddress.noDelay, socketFamily);
	}
	else
	{
		netsResult = connectStreamClientHostname(
			streamClient, connectData->byHostname.hostname, connectData->byHostname.service, 
			connectData->byHostname.noDelay, connectData->byHostname.setSNI, IP_V6_SOCKET_FAMILY);
		if (netsResult != SUCCESS_NETS_RESULT)
		{
			netsResult = connectStreamClientHostname(
				streamClient, connectData->byHostname.hostname, connectData->byHostname.service, 
				connectData->byHostname.noDelay, connectData->byHostname.setSNI, IP_V4_SOCKET_FAMILY);
		}
	}
	destroyStreamClientConnect(connectData);

	if (netsResult == SUCCESS_NETS_RESULT)
		streamClient->isConnected = true;
	streamClient->onConnection(streamClient, netsResult);

	if (netsResult != SUCCESS_NETS_RESULT)
	{
		streamClient->isRunning = false;
		return;
	}

	#if __linux__ || __APPLE__
	int eventPool = streamClient->eventPool;

	#if __linux__
	struct epoll_event event;
	#elif __APPLE__
	struct kevent event;
	#endif

	while (streamClient->isRunning)
	{
		#if __linux__
		int eventCount = epoll_wait(eventPool, &event, 1, -1);
		#elif __APPLE__
		int eventCount = kevent(eventPool, NULL, 0, &event, 1, NULL);
		#endif

		if (eventCount == -1)
		{
			streamClient->isRunning = streamClient->isConnected = false;
			return;
		}

		#if __linux__
		void* eventData = event.data.ptr;
		#elif __APPLE__
		void* eventData = event.udata;
		#endif

		if (eventData == NULL) // Note: client has been waked up.
		{
			#if __linux__
			uint64_t count;
			if (read(streamClient->wakeupEvent, &count, sizeof(uint64_t)) != sizeof(uint64_t))
			{
				while (true)
				{
					ssize_t result = read(streamClient->wakeupEvent, &count, sizeof(uint64_t));
					if (result == -1 && errno == EAGAIN)
						break;
				}
			}
			#endif
		}
		#if __APPLE__
		else if (event.flags & (EV_EOF | EV_ERROR))
		{
			streamClient->isRunning = streamClient->isConnected = false;
			return;
		}
		#endif

		processStreamClient(streamClient);
	}
	#elif _WIN32
	while (streamClient->isRunning)
	{
		processStreamClient(streamClient);
		sleepThread(0.001f); // TODO: suboptimal, use IOCP or RIO instead on Windows.
	}
	#endif
}

//**********************************************************************************************************************
NetsResult createStreamClient(size_t bufferSize, double timeoutTime, OnStreamClientConnection onConnection,
	OnStreamClientReceive onReceive, void* handle, SslContext sslContext, StreamClient* streamClient)
{
	assert(bufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(onConnection);
	assert(onReceive);
	assert(streamClient);

	StreamClient streamClientInstance = calloc(1, sizeof(StreamClient_T));
	if (!streamClientInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	streamClientInstance->timeoutTime = timeoutTime;
	streamClientInstance->onConnection = onConnection;
	streamClientInstance->onReceive = onReceive;
	streamClientInstance->handle = handle;
	streamClientInstance->sslContext = sslContext;

	uint8_t* buffer = malloc(bufferSize * sizeof(uint8_t));
	if (!buffer)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	streamClientInstance->buffer = buffer;
	streamClientInstance->bufferSize = bufferSize;

	#if __linux__
	int wakeupEvent = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (wakeupEvent == -1)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamClientInstance->wakeupEvent = wakeupEvent;

	int eventPool = epoll_create1(EPOLL_CLOEXEC);
	if (eventPool == -1)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamClientInstance->eventPool = eventPool;

	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.ptr = NULL;

	if (epoll_ctl(eventPool, EPOLL_CTL_ADD, wakeupEvent, &event) == -1)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	#elif __APPLE__
	int eventPool = kqueue();
	if (eventPool == -1)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamClientInstance->eventPool = eventPool;
	
	if (fcntl(eventPool, F_SETFD, FD_CLOEXEC) == -1)
	{
		destroyStreamClient(streamClientInstance);
		return FAILED_TO_SET_FLAG_NETS_RESULT;
	}

	struct kevent event;
	EV_SET(&event, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);

	if (kevent(eventPool, &event, 1, NULL, 0, NULL) == -1)
	{
		destroyStreamClient(streamClientInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	#elif _WIN32
	// TODO: implement.
	#endif

	*streamClient = streamClientInstance;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
static void wakeUpStreamClient(StreamClient streamClient)
{
	#if __linux__
	uint64_t wakeupData = 1;
	ssize_t result = write(streamClient->wakeupEvent, &wakeupData, sizeof(uint64_t));
	assert(result == sizeof(uint64_t));
	#elif __APPLE__
	struct kevent event;
	EV_SET(&event, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	kevent(streamClient->eventPool, &event, 1, NULL, 0, NULL);
	#endif
}
inline static void stopStreamClientReceive(StreamClient streamClient)
{
	streamClient->isRunning = streamClient->isConnected = false;
	wakeUpStreamClient(streamClient);

	Thread receiveThread = streamClient->receiveThread;
	joinThread(receiveThread);
	destroyThread(receiveThread);
}
void destroyStreamClient(StreamClient streamClient)
{
	if (!streamClient)
		return;

	if (streamClient->receiveThread)
		stopStreamClientReceive(streamClient);

	#if __linux__
	if (streamClient->wakeupEvent > 0)
		close(streamClient->wakeupEvent);
	#endif
	#if __linux__ || __APPLE__
	if (streamClient->eventPool > 0)
		close(streamClient->eventPool);
	#endif

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
double getStreamClientTimeoutTime(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->timeoutTime;
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

SslContext getStreamClientSslContext(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->sslContext;
}
void setStreamClientSslContext(StreamClient streamClient, SslContext sslContext)
{
	assert(streamClient);
	assert(!streamClient->isRunning);
	streamClient->sslContext = sslContext;
}

//**********************************************************************************************************************
bool isStreamClientRunning(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->isRunning;
}
bool isStreamClientConnected(StreamClient streamClient)
{
	assert(streamClient);
	return streamClient->isConnected;
}

NetsResult connectStreamClientByAddress(StreamClient streamClient, 
	SocketAddress remoteAddress, const char* hostname, bool noDelay)
{
	assert(streamClient);
	assert(remoteAddress);
	assert(!streamClient->receiveThread);

	StreamClientConnect* connectData = calloc(1, sizeof(StreamClientConnect));
	if (!connectData)
		return OUT_OF_MEMORY_NETS_RESULT;

	connectData->byAddress.streamClient = streamClient;
	connectData->byAddress.isByAddress = true;
	connectData->byAddress.noDelay = noDelay;

	if (hostname)
	{
		size_t hostnameLenght = strlen(hostname);
		assert(hostnameLenght > 0);

		connectData->byAddress.hostname = malloc(hostnameLenght);
		if (!connectData->byAddress.hostname)
		{
			destroyStreamClientConnect(connectData);
			return OUT_OF_MEMORY_NETS_RESULT;
		}
		memcpy(connectData->byAddress.hostname, hostname, hostnameLenght * sizeof(char));
	}

	connectData->byAddress.remoteAddress = createSocketAddressCopy(remoteAddress);
	if (!connectData->byAddress.remoteAddress)
	{
		destroyStreamClientConnect(connectData);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	streamClient->isRunning = true;
	Thread receiveThread = createThread(streamClientReceive, connectData);
	if (receiveThread == NULL)
	{
		streamClient->isRunning = false;
		destroyStreamClientConnect(connectData);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	streamClient->receiveThread = receiveThread;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
NetsResult connectStreamClientByHostname(StreamClient streamClient, 
	const char* hostname, const char* service, bool noDelay, bool setSNI)
{
	assert(streamClient);
	assert(hostname);
	assert(service);
	assert(!streamClient->receiveThread);

	StreamClientConnect* connectData = calloc(1, sizeof(StreamClientConnect));
	if (!connectData)
		return OUT_OF_MEMORY_NETS_RESULT;

	connectData->byHostname.streamClient = streamClient;
	connectData->byHostname.isByAddress = false;
	connectData->byHostname.noDelay = noDelay;
	connectData->byHostname.setSNI = setSNI;

	size_t hostnameLenght = strlen(hostname);
	assert(hostnameLenght > 0);

	connectData->byHostname.hostname = malloc(hostnameLenght);
	if (!connectData->byHostname.hostname)
	{
		destroyStreamClientConnect(connectData);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	memcpy(connectData->byHostname.hostname, hostname, hostnameLenght * sizeof(char));

	size_t serviceLenght = strlen(hostname);
	assert(serviceLenght > 0);

	connectData->byHostname.service = malloc(serviceLenght);
	if (!connectData->byHostname.service)
	{
		destroyStreamClientConnect(connectData);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	memcpy(connectData->byHostname.service, service, serviceLenght * sizeof(char));

	streamClient->isRunning = true;
	Thread receiveThread = createThread(streamClientReceive, connectData);
	if (receiveThread == NULL)
	{
		streamClient->isRunning = false;
		destroyStreamClientConnect(connectData);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	streamClient->receiveThread = receiveThread;
	return SUCCESS_NETS_RESULT;
}

void disconnectStreamClient(StreamClient streamClient)
{
	assert(streamClient);
	if (streamClient->receiveThread)
	{
		stopStreamClientReceive(streamClient);
		streamClient->receiveThread = NULL;
	}

	if (streamClient->socket)
	{
		Socket socket = streamClient->socket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
		streamClient->socket = NULL;
		streamClient->lastReceiveTime = 0.0;
	}
}
void stopStreamClient(StreamClient streamClient)
{
	assert(streamClient);
	streamClient->isRunning = streamClient->isConnected = false;
}

//**********************************************************************************************************************
void updateStreamClient(StreamClient streamClient)
{
	wakeUpStreamClient(streamClient);
}

NetsResult streamClientSend(StreamClient streamClient, const void* sendBuffer, size_t byteCount)
{
	assert(streamClient);
	if (!streamClient->isConnected)
		return CONNECTION_IS_CLOSED_NETS_RESULT;
	NetsResult netsResult = socketSend(streamClient->socket, sendBuffer, byteCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;
	return SUCCESS_NETS_RESULT;
}