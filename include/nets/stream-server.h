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

/***********************************************************************************************************************
 * @file
 * @brief Network stream server functions. (TCP)
 */

#pragma once
#include "nets/socket.h"

typedef struct StreamServer_T StreamServer_T;   /**< Stream server structure. (TCP) */
typedef StreamServer_T* StreamServer;           /**< Stream server instance. (TCP) */
typedef struct StreamSession_T StreamSession_T; /**< Stream server session structure. (TCP) */
typedef StreamSession_T* StreamSession;         /**< Stream server session instance. (TCP) */

/**
 * @brief Stream session create function. (TCP)
 * @details Server destroys session on this function false return result.
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamServer stream server instance
 * @param streamSession a new accepted stream session instance
 * @param[out] handle pointer to the custom session handle
 */
typedef bool(*OnStreamSessionCreate)(StreamServer streamServer, StreamSession streamSession, void** handle);
/**
 * @brief Stream session destroy function. (TCP)
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamServer stream server instance
 * @param streamSession stream session instance
 * @param reason session destruction reason
 */
typedef void(*OnStreamSessionDestroy)(StreamServer streamServer, StreamSession streamSession, int reason);
/**
 * @brief Stream session data receive function. (TCP)
 * @details Server destroys session on this function non zero return result.
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamServer stream server instance
 * @param streamSession stream session instance
 * @param[in] receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef int(*OnStreamSessionReceive)(StreamServer streamServer, 
	StreamSession streamSession, const uint8_t* receiveBuffer, size_t byteCount);
/**
 * @brief Stream server datagram receive function. (UDP)
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamServer stream server instance
 * @param remoteAddress sender socket remote address
 * @param[in] receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef void(*OnStreamServerDatagram)(StreamServer streamServer, 
	SocketAddress remoteAddress, const uint8_t* receiveBuffer, size_t byteCount);

/***********************************************************************************************************************
 * @brief Creates a new stream server instance. (TCP)
 * @return The operation @ref NetsResult code.
 *
 * @param socketFamily local socket IP address family
 * @param[in] service local IP address service string (port)
 * @param sessionBufferSize session buffer size
 * @param connectionQueueSize pending connections queue size
 * @param receiveBufferSize receive data buffer size in bytes
 * @param timeoutTime session timeout time in seconds
 * @param[in] onCreate on session create function
 * @param[in] onDestroy on session destroy function
 * @param[in] onReceive on session data receive function
 * @param[in] onDatagram on datagram receive function or NULL
 * @param[in] handle receive function argument or NULL
 * @param sslContext socket SSL context instance or NULL
 * @param[out] streamServer pointer to the stream server instance
 */
NetsResult createStreamServer(SocketFamily socketFamily, const char* service, size_t sessionBufferSize, 
	size_t connectionQueueSize, size_t receiveBufferSize, double timeoutTime, OnStreamSessionCreate onCreate, 
	OnStreamSessionDestroy onDestroy, OnStreamSessionReceive onReceive, OnStreamServerDatagram onDatagram, 
	void* handle, SslContext sslContext, StreamServer* streamServer);
/**
 * @brief Destroys stream server instance. (TCP)
 * @param streamServer target stream server instance or NULL
 */
void destroyStreamServer(StreamServer streamServer);

/**
 * @brief Returns stream server session buffer size.
 * @param streamServer target stream server instance
 */
size_t getStreamServerSessionBufferSize(StreamServer streamServer);
/**
 * @brief Returns stream server receive buffer size in bytes.
 * @param streamServer target stream server instance
 */
size_t getStreamServerReceiveBufferSize(StreamServer streamServer);
/**
 * @brief Returns stream server session create function.
 * @param streamServer target stream server instance
 */
OnStreamSessionCreate getStreamServerOnCreate(StreamServer streamServer);
/**
 * @brief Returns stream server session destroy function.
 * @param streamServer target stream server instance
 */
OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer streamServer);
/**
 * @brief Returns stream server session data receive function.
 * @param streamServer target stream server instance
 */
OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer);
/**
 * @brief Returns stream server datagram receive function.
 * @param streamServer target stream server instance
 */
OnStreamServerDatagram getStreamServerOnDatagram(StreamServer streamServer);
/**
 * @brief Returns stream server session timeout time. (in seconds)
 * @param streamServer target stream server instance
 */
double getStreamServerTimeoutTime(StreamServer streamServer);
/**
 * @brief Returns stream server handle.
 * @param streamServer target stream server instance
 */
void* getStreamServerHandle(StreamServer streamServer);
/**
 * @brief Returns stream server receive data buffer.
 * @param streamServer target stream server instance
 */
uint8_t* getStreamServerReceiveBuffer(StreamServer streamServer);
/**
 * @brief Returns stream server socket instance.
 * @param streamServer target stream server instance
 */
Socket getStreamServerSocket(StreamServer streamServer);
/**
 * @brief Returns stream server datagram socket instance.
 * @param streamServer target stream server instance
 */
Socket getStreamServerDatagramSocket(StreamServer streamServer);
/**
 * @brief Returns true if stream server receive thread is running. (MT-Safe)
 * @param streamServer target stream server instance
 */
bool isStreamServerRunning(StreamServer streamServer);
/**
 * @brief Returns true if stream server use encrypted connection.
 * @param streamServer target stream server instance
 */
bool isStreamServerSecure(StreamServer streamServer);

/***********************************************************************************************************************
 * @brief Locks stream server session buffer access. (MT-Safe)
 * @param streamServer target stream server instance
 */
void lockStreamServerSessions(StreamServer streamServer);
/**
 * @brief Unlocks stream server session buffer access. (MT-Safe)
 * @param streamServer target stream server instance
 */
void unlockStreamServerSessions(StreamServer streamServer);
/**
 * @brief Returns stream server session buffer.
 * @warning You should lock sessions before getting!
 * @param streamServer target stream server instance
 */
StreamSession* getStreamServerSessions(StreamServer streamServer);
/**
 * @brief Returns stream server session buffer.
 * @warning You should lock sessions before getting count!
 * @param streamServer target stream server instance
 */
size_t getStreamServerSessionCount(StreamServer streamServer);

/**
 * @brief Returns stream session socket instance.
 * @warning You should lock sessions before getting socket!
 * @param streamSession target stream session instance
 */
Socket getStreamSessionSocket(StreamSession streamSession);
/**
 * @brief Returns stream session remote IP address instance.
 * @param streamSession target stream session instance
 */
SocketAddress getStreamSessionRemoteAddress(StreamSession streamSession);
/**
 * @brief Returns stream session handle.
 * @param streamSession target stream session instance
 */
void* getStreamSessionHandle(StreamSession streamSession);

/**
 * @brief Updates specified stream server session state.
 * @warning You should lock sessions before updating!
 * @return Zero on success, otherwise failure reason.
 *
 * @param streamServer target stream server instance
 * @param streamSession stream session instance to update
 * @param currentTime current time value
 */
int updateStreamSession(StreamServer streamServer, StreamSession streamSession, double currentTime);
/**
 * @brief Closes specified stream server session.
 * @warning You should lock sessions before closing!
 *
 * @param streamServer target stream server instance
 * @param streamSession stream session instance to close
 * @param reason stream session destruction reason
 */
void closeStreamSession(StreamServer streamServer, StreamSession streamSession, int reason);
/**
 * @brief Resets specified stream server session timeout time.
 * @warning You should lock sessions before aliving!
 * @param streamSession target stream session instance
 */
void aliveStreamSession(StreamSession streamSession);

/**
 * @brief Sends stream data to the specified session. (TCP)
 * @warning You should lock sessions before sending messages!
 * @return The operation @ref NetsResult code.
 *
 * @param streamSession target stream session instance
 * @param[in] data send data buffer
 * @param byteCount data byte count to send
 */
NetsResult streamSessionSend(StreamSession streamSession, const void* data, size_t byteCount);
/**
 * @brief Sends datagram to the specified stream session. (UDP)
 * @warning You should lock sessions before sending messages!
 * @return The operation @ref NetsResult code.
 *
 * @param streamServer stream server instance
 * @param streamSession target stream session instance
 * @param[in] data send data buffer
 * @param byteCount data byte count to send
 */
NetsResult streamSessionSendDatagram(StreamServer streamServer, 
	StreamSession streamSession, const void* data, size_t byteCount);

/**
 * @brief Shutdowns part of the full-duplex socket connection.
 * @return The operation @ref NetsResult code.
 *
 * @param streamSession target stream session instance
 * @param shutdown socket connection shutdown mode
 */
NetsResult shutdownStreamSession(StreamSession streamSession, SocketShutdown shutdown);