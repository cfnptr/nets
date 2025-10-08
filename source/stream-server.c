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

#include "nets/stream-server.h"
#include "mpmt/thread.h"
#include "mpmt/sync.h"
#include "mpio/os.h"
#include <string.h>

#if __linux__
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#elif __APPLE__
#include <fcntl.h>
#include <unistd.h>
#include <sys/event.h>
#endif

struct StreamSession_T
{
	Socket receiveSocket;
	SocketAddress remoteAddress;
	void* handle;
	double lastReceiveTime;
};
struct StreamServer_T
{
	double timeoutTime;
	OnStreamSessionCreate onCreate;
	OnStreamSessionDestroy onDestroy;
	OnStreamSessionReceive onReceive;
	OnStreamServerDatagram onDatagram;
	void* handle;
	uint8_t* receiveBuffer;
	size_t receiveBufferSize;
	StreamSession* sessionBuffer;
	size_t sessionBufferSize;
	size_t sessionCount;
	Socket streamSocket;
	Socket datagramSocket;
	SocketAddress datagramAddress;
	Mutex sessionLocker;
	Thread receiveThread; // TODO: distribute clients receive accross different threads with separate event pools.
	#if __linux__ || __APPLE__
	int eventPool;
	#endif
	#if __linux__
	int wakeupEvent;
	#endif
	volatile bool disconnectSessions;
	volatile bool isRunning;
};

//**********************************************************************************************************************
inline static void destroyStreamSession(StreamSession streamSession)
{
	if (!streamSession)
		return;

	if (streamSession->receiveSocket)
	{
		Socket receiveSocket = streamSession->receiveSocket;
		shutdownSocket(receiveSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	}

	destroySocketAddress(streamSession->remoteAddress);
	free(streamSession);
}
inline static bool acceptStreamSession(StreamServer streamServer, 
	Socket acceptedSocket, StreamSession* _streamSession, bool useSSL)
{
	if (streamServer->sessionCount >= streamServer->sessionBufferSize)
	{
		shutdownSocket(acceptedSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(acceptedSocket);
		return false;
	}

	StreamSession streamSession = calloc(1, sizeof(StreamSession_T));
	if (!streamSession)
		return false;
	streamSession->receiveSocket = acceptedSocket;

	SocketAddress remoteAddress;
	if (createAnySocketAddress(IP_V6_SOCKET_FAMILY, &remoteAddress) != SUCCESS_NETS_RESULT)
	{
		destroyStreamSession(streamSession);
		return false;
	}
	streamSession->remoteAddress = remoteAddress;

	if (!getSocketRemoteAddress(acceptedSocket, remoteAddress))
	{
		destroyStreamSession(streamSession);
		return false;
	}

	void* sessionHandle = NULL;
	if (!streamServer->onCreate(streamServer, streamSession, &sessionHandle))
	{
		destroyStreamSession(streamSession);
		return false;
	}

	streamSession->handle = sessionHandle;
	streamSession->lastReceiveTime = getCurrentClock(); // Note: getting latest time here.

	#if NETS_SUPPORT_OPENSSL
	if (useSSL) // Note: indicates if we should also establish SSL connection.
		streamSession->lastReceiveTime = -streamSession->lastReceiveTime;
	#endif

	streamServer->sessionBuffer[streamServer->sessionCount++] = streamSession;
	*_streamSession = streamSession;
	return true;
}

//**********************************************************************************************************************
inline static void disconnectStreamSession(StreamServer streamServer, StreamSession streamSession, int reason)
{
	Mutex sessionLocker = streamServer->sessionLocker;
	lockMutex(sessionLocker);

	if (!streamSession->receiveSocket) // Note: stream session is already disconnected.
	{
		unlockMutex(sessionLocker);
		return;
	}

	Socket receiveSocket = streamSession->receiveSocket;
	streamSession->receiveSocket = NULL;
	shutdownSocket(receiveSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(receiveSocket);
	
	unlockMutex(sessionLocker);
	streamServer->disconnectSessions = true;
	
	streamServer->onDestroy(streamServer, streamSession, reason);
}
inline static void disconnectStreamSessions(StreamServer streamServer)
{
	if (!streamServer->disconnectSessions)
		return;

	Mutex sessionLocker = streamServer->sessionLocker;
	lockMutex(sessionLocker);

	StreamSession* sessionBuffer = streamServer->sessionBuffer;
	size_t sessionCount = streamServer->sessionCount;
	
	for (int64_t i = sessionCount - 1; i >= 0; i--)
	{
		StreamSession streamSession = sessionBuffer[i];
		if (streamSession->receiveSocket)
			continue;

		destroySocketAddress(streamSession->remoteAddress);
		free(streamSession);

		for (size_t j = i + 1; j < sessionCount; j++)
			sessionBuffer[j - 1] = sessionBuffer[j];
		sessionCount--;
	}
	streamServer->sessionCount = sessionCount;

	unlockMutex(sessionLocker);
	streamServer->disconnectSessions = false;
}

//**********************************************************************************************************************
inline static void processStreamSession(StreamServer streamServer, StreamSession streamSession)
{
	Socket receiveSocket = streamSession->receiveSocket;
	if (!receiveSocket) // Note: stream session is disconnected.
		return;

	double lastReceiveTime = streamSession->lastReceiveTime;
	double currentTime = getCurrentClock();

	#if NETS_SUPPORT_OPENSSL
	if (lastReceiveTime < 0.0) // Note: we should first establish SSL connection.
	{
		if (currentTime + lastReceiveTime > streamServer->timeoutTime)
		{
			disconnectStreamSession(streamServer, streamSession, TIMED_OUT_NETS_RESULT);
			return;
		}

		NetsResult netsResult = acceptSslSocket(receiveSocket);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
			return;

		if (netsResult != SUCCESS_NETS_RESULT)
		{
			disconnectStreamSession(streamServer, streamSession, netsResult);
			return;
		}
		streamSession->lastReceiveTime = currentTime;
	}
	else
	#endif
	{
		if (currentTime - lastReceiveTime > streamServer->timeoutTime)
		{
			disconnectStreamSession(streamServer, streamSession, TIMED_OUT_NETS_RESULT);
			return;
		}
	}

	OnStreamSessionReceive onReceive = streamServer->onReceive;
	uint8_t* receiveBuffer = streamServer->receiveBuffer;
	size_t receiveBufferSize = streamServer->receiveBufferSize;
	size_t byteCount;

	while (streamServer->isRunning)
	{
		NetsResult netsResult = socketReceive(receiveSocket, receiveBuffer, receiveBufferSize, &byteCount);
		if (netsResult == IN_PROGRESS_NETS_RESULT)
		{
			streamSession->lastReceiveTime = getCurrentClock(); // Note: getting latest time here.
			return;
		}

		if (netsResult != SUCCESS_NETS_RESULT)
		{
			disconnectStreamSession(streamServer, streamSession, netsResult);
			return;
		}
		if (byteCount == 0)
		{
			disconnectStreamSession(streamServer, streamSession, CONNECTION_IS_CLOSED_NETS_RESULT);
			return;
		}

		int reason = onReceive(streamServer, streamSession, receiveBuffer, byteCount);
		if (reason != SUCCESS_NETS_RESULT)
		{
			disconnectStreamSession(streamServer, streamSession, reason);
			return;
		}
	}
}

inline static void processStreamDatagrams(StreamServer streamServer)
{
	OnStreamServerDatagram onDatagram = streamServer->onDatagram;
	Socket datagramSocket = streamServer->datagramSocket;
	SocketAddress remoteAddress = streamServer->datagramAddress;
	uint8_t* receiveBuffer = streamServer->receiveBuffer;
	size_t receiveBufferSize = streamServer->receiveBufferSize;
	size_t byteCount;

	while (streamServer->isRunning)
	{
		NetsResult netsResult = socketReceiveFrom(datagramSocket, 
			remoteAddress, receiveBuffer, receiveBufferSize, &byteCount);
		if (netsResult != SUCCESS_NETS_RESULT)
			return;
		onDatagram(streamServer, remoteAddress, receiveBuffer, byteCount);
	}
}

//**********************************************************************************************************************
inline static void streamServerReceive(void* argument)
{
	setThreadName("RECV");
	setThreadForegroundPriority();

	#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_IGN);
	#endif

	StreamServer streamServer = (StreamServer)argument;
	Socket streamSocket = streamServer->streamSocket;
	Socket datagramSocket = streamServer->datagramSocket;
	Socket acceptedSocket; StreamSession streamSession;

	#if NETS_SUPPORT_OPENSSL
	bool useSSL = getSocketSslContext(streamSocket) != NULL;
	#else
	const bool useSSL = false;
	#endif

	#if __linux__ || __APPLE__
	int eventPool = streamServer->eventPool;

	#if __linux__
	struct epoll_event event, events[64];
	#elif __APPLE__
	struct kevent event, events[64];
	#endif

	while (streamServer->isRunning)
	{
		#if __linux__
		int eventCount = epoll_wait(eventPool, events, 64, -1);
		#elif __APPLE__
		int eventCount = kevent(eventPool, NULL, 0, events, 64, NULL);
		#endif

		if (eventCount == -1)
		{
			streamServer->isRunning = false;
			return;
		}

		for (int i = 0; i < eventCount; i++)
		{
			#if __linux__
			void* eventData = events[i].data.ptr;
			#elif __APPLE__
			void* eventData = events[i].udata;
			#endif

			if (eventData == streamSocket)
			{
				while (streamServer->isRunning)
				{
					NetsResult netsResult = acceptSocket(streamSocket, &acceptedSocket);
					if (netsResult == IN_PROGRESS_NETS_RESULT)
						break;
					if (netsResult != SUCCESS_NETS_RESULT)
						continue;
					if (!acceptStreamSession(streamServer, acceptedSocket, &streamSession, useSSL))
						continue;

					int socketHandle = (int)(size_t)getSocketHandle(acceptedSocket);

					#if __linux__
					event.events = EPOLLIN | EPOLLET;
					event.data.ptr = streamSession;
					int eventResult = epoll_ctl(eventPool, EPOLL_CTL_ADD, socketHandle, &event);
					#elif __APPLE__
					EV_SET(&event, socketHandle, EVFILT_READ, EV_ADD, 0, 0, streamSession);
					int eventResult = kevent(eventPool, &event, 1, NULL, 0, NULL);
					#endif

					if (eventResult == -1)
					{
						disconnectStreamSession(streamServer, streamSession, OUT_OF_MEMORY_NETS_RESULT);
						continue;
					}
				}
			}
			else if (eventData == datagramSocket)
			{
				processStreamDatagrams(streamServer);
			}
			#if __APPLE__
			else if (events[i].flags & (EV_EOF | EV_ERROR))
			{
				disconnectStreamSession(streamServer, (StreamSession)eventData, CONNECTION_IS_CLOSED_NETS_RESULT);
			}
			#endif
			else if (eventData == NULL) // Note: server has been stopped.
			{
				streamServer->isRunning = false;
				return;
			}
			else
			{
				processStreamSession(streamServer, (StreamSession)eventData);
			}
		}

		disconnectStreamSessions(streamServer);
	}
	#elif _WIN32
	while (streamServer->isRunning)
	{
		while (streamServer->isRunning)
		{
			NetsResult netsResult = acceptSocket(streamSocket, &acceptedSocket);
			if (netsResult == IN_PROGRESS_NETS_RESULT)
				break;
			if (netsResult != SUCCESS_NETS_RESULT)
				continue;
			if (!acceptStreamSession(streamServer, acceptedSocket, &streamSession, useSSL))
				continue;
		}
		
		StreamSession* sessionBuffer = streamServer->sessionBuffer;
		size_t sessionCount = streamServer->sessionCount;
		for (size_t i = 0; i < sessionCount; i++)
			processStreamSession(streamServer, sessionBuffer[i]);

		disconnectStreamSessions(streamServer);
		if (streamServer->onDatagram)
			processStreamDatagrams(streamServer);
		sleepThread(0.001f); // TODO: suboptimal, use IOCP or RIO instead on Windows.
	}
	#endif
}

//**********************************************************************************************************************
NetsResult createStreamServer(SocketFamily socketFamily, const char* service, size_t sessionBufferSize, 
	size_t connectionQueueSize, size_t receiveBufferSize, double timeoutTime, OnStreamSessionCreate onCreate, 
	OnStreamSessionDestroy onDestroy, OnStreamSessionReceive onReceive, OnStreamServerDatagram onDatagram, 
	void* handle, SslContext sslContext, StreamServer* streamServer)
{
	assert(socketFamily < SOCKET_FAMILY_COUNT);
	assert(service);
	assert(strlen(service) > 0);
	assert(sessionBufferSize > 0);
	assert(connectionQueueSize > 0);
	assert(receiveBufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(onCreate);
	assert(onDestroy);
	assert(onReceive);
	assert(streamServer);

	StreamServer streamServerInstance = calloc(1, sizeof(StreamServer_T));
	if (!streamServerInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	streamServerInstance->timeoutTime = timeoutTime;
	streamServerInstance->onCreate = onCreate;
	streamServerInstance->onDestroy = onDestroy;
	streamServerInstance->onReceive = onReceive;
	streamServerInstance->onDatagram = onDatagram;
	streamServerInstance->handle = handle;

	uint8_t* receiveBuffer = malloc(receiveBufferSize * sizeof(uint8_t));
	if (!receiveBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	streamServerInstance->receiveBuffer = receiveBuffer;
	streamServerInstance->receiveBufferSize = receiveBufferSize;

	StreamSession* sessionBuffer = malloc(sessionBufferSize * sizeof(StreamSession));
	if (!sessionBuffer)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	streamServerInstance->sessionBufferSize = sessionBufferSize;
	streamServerInstance->sessionBuffer = sessionBuffer;
	streamServerInstance->sessionCount = 0;
	streamServerInstance->disconnectSessions = false;

	SocketAddress socketAddress;
	NetsResult netsResult = createSocketAddress(socketFamily == IP_V4_SOCKET_FAMILY ?
		ANY_IP_ADDRESS_V4 : ANY_IP_ADDRESS_V6, service, &socketAddress);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return netsResult;
	}
	streamServerInstance->datagramAddress = socketAddress;

	Socket streamSocket;
	netsResult = createSocket(STREAM_SOCKET_TYPE, socketFamily, 
		socketAddress, false, false, sslContext, &streamSocket);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return netsResult;
	}
	streamServerInstance->streamSocket = streamSocket;

	netsResult = listenSocket(streamSocket, connectionQueueSize);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroyStreamServer(streamServerInstance);
		return netsResult;
	}

	Socket datagramSocket = NULL;
	if (onDatagram)
	{
		netsResult = createSocket(DATAGRAM_SOCKET_TYPE, socketFamily, 
			socketAddress, false, false, NULL, &datagramSocket);
		if (netsResult != SUCCESS_NETS_RESULT)
		{
			destroyStreamServer(streamServerInstance);
			return netsResult;
		}
		streamServerInstance->datagramSocket = datagramSocket;
	}
	else
	{
		destroySocketAddress(socketAddress);
		streamServerInstance->datagramAddress = NULL;
	}
	
	int streamHandle = (int)(size_t)getSocketHandle(streamSocket);
	#if __linux__
	int wakeupEvent = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (wakeupEvent == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamServerInstance->wakeupEvent = wakeupEvent;

	int eventPool = epoll_create1(EPOLL_CLOEXEC);
	if (eventPool == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamServerInstance->eventPool = eventPool;

	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.ptr = NULL;

	if (epoll_ctl(eventPool, EPOLL_CTL_ADD, wakeupEvent, &event) == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}

	event.data.ptr = streamSocket;
	if (epoll_ctl(eventPool, EPOLL_CTL_ADD, streamHandle, &event) == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}

	if (datagramSocket)
	{
		int datagramHandle = (int)(size_t)getSocketHandle(datagramSocket);
		event.events = EPOLLIN | EPOLLET;
		event.data.ptr = datagramSocket;

		if (epoll_ctl(eventPool, EPOLL_CTL_ADD, datagramHandle, &event) == -1)
		{
			destroyStreamServer(streamServerInstance);
			return OUT_OF_DESCRIPTORS_NETS_RESULT;
		}
	}
	#elif __APPLE__
	int eventPool = kqueue();
	if (eventPool == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	streamServerInstance->eventPool = eventPool;

	if (fcntl(eventPool, F_SETFD, FD_CLOEXEC) == -1)
	{
		destroyStreamServer(streamServerInstance);
		return FAILED_TO_SET_FLAG_NETS_RESULT;
	}

	struct kevent events[3]; int eventCount = 2;
	EV_SET(&events[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	EV_SET(&events[1], streamHandle, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, streamSocket);

	if (datagramSocket)
	{
		int datagramHandle = (int)(size_t)getSocketHandle(datagramSocket);
		EV_SET(&events[eventCount++], datagramHandle, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, datagramSocket);
	}

	if (kevent(eventPool, events, eventCount, NULL, 0, NULL) == -1)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	}
	#elif _WIN32
	// TODO: implement.
	#endif

	Mutex sessionLocker = createMutex();
	if (!sessionLocker)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	streamServerInstance->sessionLocker = sessionLocker;

	streamServerInstance->isRunning = true;
	Thread receiveThread = createThread(streamServerReceive, streamServerInstance);
	if (receiveThread == NULL)
	{
		destroyStreamServer(streamServerInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}
	streamServerInstance->receiveThread = receiveThread;

	*streamServer = streamServerInstance;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
void destroyStreamServer(StreamServer streamServer)
{
	if (!streamServer)
		return;

	if (streamServer->receiveThread)
	{
		streamServer->isRunning = false;

		#if __linux__
		uint64_t wakeupData = 1;
		ssize_t result = write(streamServer->wakeupEvent, &wakeupData, sizeof(uint64_t));
		assert(result == sizeof(uint64_t));
		#elif __APPLE__
		struct kevent event;
		EV_SET(&event, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
		kevent(streamServer->eventPool, &event, 1, NULL, 0, NULL);
		#endif

		Thread receiveThread = streamServer->receiveThread;
		joinThread(receiveThread);
		destroyThread(receiveThread);
	}

	StreamSession* sessionBuffer = streamServer->sessionBuffer;
	size_t sessionCount = streamServer->sessionCount;
	OnStreamSessionDestroy onDestroy = streamServer->onDestroy;

	for (size_t i = 0; i < sessionCount; i++)
	{
		StreamSession streamSession = sessionBuffer[i];
		if (!streamSession->receiveSocket)
			continue;

		Socket receiveSocket = streamSession->receiveSocket;
		shutdownSocket(receiveSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(receiveSocket);
	
		onDestroy(streamServer, streamSession, CONNECTION_IS_CLOSED_NETS_RESULT);
		destroySocketAddress(streamSession->remoteAddress);
		free(streamSession);
	}

	#if __linux__
	if (streamServer->wakeupEvent > 0)
		close(streamServer->wakeupEvent);
	#endif
	#if __linux__ || __APPLE__
	if (streamServer->eventPool > 0)
		close(streamServer->eventPool);
	#endif

	if (streamServer->datagramSocket)
	{
		Socket socket = streamServer->datagramSocket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}
	if (streamServer->streamSocket)
	{
		Socket socket = streamServer->streamSocket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	destroyMutex(streamServer->sessionLocker);
	destroySocketAddress(streamServer->datagramAddress);
	free(streamServer->receiveBuffer);
	free(sessionBuffer);
	free(streamServer);
}

//**********************************************************************************************************************
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
OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onReceive;
}
OnStreamServerDatagram getStreamServerOnDatagram(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->onDatagram;
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
uint8_t* getStreamServerReceiveBuffer(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->receiveBuffer;
}
Socket getStreamServerSocket(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->streamSocket;
}
Socket getStreamServerDatagramSocket(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->datagramSocket;
}
bool isStreamServerRunning(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->isRunning;
}
bool isStreamServerSecure(StreamServer streamServer)
{
	assert(streamServer);
	return getSocketSslContext(streamServer->streamSocket) != NULL;
}

//**********************************************************************************************************************
Socket getStreamSessionSocket(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->receiveSocket;
}
SocketAddress getStreamSessionRemoteAddress(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->remoteAddress;
}
void* getStreamSessionHandle(StreamSession streamSession)
{
	assert(streamSession);
	return streamSession->handle;
}

void lockStreamServerSessions(StreamServer streamServer)
{
	assert(streamServer);
	lockMutex(streamServer->sessionLocker);
}
void unlockStreamServerSessions(StreamServer streamServer)
{
	assert(streamServer);
	unlockMutex(streamServer->sessionLocker);
}
StreamSession* getStreamServerSessions(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->sessionBuffer;
}
size_t getStreamServerSessionCount(StreamServer streamServer)
{
	assert(streamServer);
	return streamServer->sessionCount;
}

int updateStreamSession(StreamServer streamServer, StreamSession streamSession, double currentTime)
{
	assert(streamServer);
	assert(streamSession);
	if (currentTime - streamSession->lastReceiveTime > streamServer->timeoutTime)
		return TIMED_OUT_NETS_RESULT;
	return SUCCESS_NETS_RESULT;
}
void closeStreamSession(StreamServer streamServer, StreamSession streamSession, int reason)
{
	assert(streamServer);
	assert(streamSession);

	if (!streamSession->receiveSocket) // Note: stream session is already closed.
		return;

	Socket receiveSocket = streamSession->receiveSocket;
	streamSession->receiveSocket = NULL;
	shutdownSocket(receiveSocket, RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(receiveSocket);
	
	streamServer->disconnectSessions = true;
	streamServer->onDestroy(streamServer, streamSession, reason);
}

NetsResult streamSessionSend(StreamSession streamSession, const void* data, size_t byteCount)
{
	assert(streamSession);
	if (!streamSession->receiveSocket)
		return CONNECTION_IS_CLOSED_NETS_RESULT;
	return socketSend(streamSession->receiveSocket, data, byteCount);
}
NetsResult streamSessionSendDatagram(StreamServer streamServer, 
	StreamSession streamSession, const void* data, size_t byteCount)
{
	assert(streamServer);
	assert(streamSession);
	assert(streamServer->datagramSocket);

	if (!streamSession->receiveSocket)
		return CONNECTION_IS_CLOSED_NETS_RESULT;
	return socketSendTo(streamServer->datagramSocket, data, 
		byteCount, streamSession->remoteAddress);
}