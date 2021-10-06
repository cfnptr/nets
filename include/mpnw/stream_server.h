// Copyright 2020-2021 Nikita Fediuchin. All rights reserved.
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

#pragma once
#include "mpnw/socket.h"

/* Stream server instance handle (TCP) */
typedef struct StreamServer* StreamServer;
/* Stream server session instance handle (TCP) */
typedef struct StreamSession* StreamSession;

/*
 * Stream session create function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionCreate)(
	StreamServer streamServer,
	Socket socket,
	void** handle);

/* Stream session destroy function */
typedef void(*OnStreamSessionDestroy)(
	StreamServer streamServer,
	StreamSession streamSession);

/*
 * Stream session update function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionUpdate)(
	StreamServer streamServer,
	StreamSession streamSession);

/*
 * Stream session receive function
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionReceive)(
	StreamServer streamServer,
	StreamSession streamSession,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Create a new stream server instance (TCP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * sessionBufferSize - socket session buffer size.
 * receiveBufferSize - socket message receive buffer size.
 * receiveTimeoutTime - socket message receive timeout time (s).
 * receiveFunction - message receive function.
 * createFunction - create function or NULL.
 * destroyFunction - destroy function or NULL.
 * handle - receive function argument.
 * sslContext - SSL context or NULL.
 */
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
	StreamServer* streamServer);

/*
 * Destroy stream server instance.
 * streamServer - stream server instance or NULL.
 */
void destroyStreamServer(StreamServer streamServer);

/*
 * Returns stream server session buffer size.
 * streamServer - stream server instance.
 */
size_t getStreamServerSessionBufferSize(StreamServer streamServer);

/*
 * Returns stream server receive buffer size.
 * streamServer - stream server instance.
 */
size_t getStreamServerReceiveBufferSize(StreamServer streamServer);

/*
 * Returns stream server create function.
 * streamServer - stream server instance.
 */
OnStreamSessionCreate getStreamServerOnCreate(StreamServer streamServer);

/*
 * Returns stream server destroy function.
 * streamServer - stream server instance.
 */
OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer streamServer);

/*
 * Returns stream server update function.
 * streamServer - stream server instance.
 */
OnStreamSessionUpdate getStreamServerOnUpdate(StreamServer streamServer);

/*
 * Returns stream server receive function.
 * streamServer - stream server instance.
 */
OnStreamSessionReceive getStreamServerOnReceive(StreamServer streamServer);

/*
 * Returns stream server handle.
 * streamServer - stream server instance.
 */
void* getStreamServerHandle(StreamServer streamServer);

/*
 * Returns stream server socket.
 * streamServer - stream server instance.
 */
Socket getStreamServerSocket(StreamServer streamServer);

/*
 * Returns stream session socket.
 * streamSession - stream session instance.
 */
Socket getStreamSessionSocket(StreamSession streamSession);

/*
 * Returns stream session handle.
 * streamSession - stream session instance.
 */
void* getStreamSessionHandle(StreamSession streamSession);

/*
 * Receive buffered datagrams.
 * Returns true if update actions occurred.
 *
 * streamServer - stream server instance.
 */
bool updateStreamServer(StreamServer streamServer);

/*
 * Send datagram to the specified session.
 * Returns true on success.
 *
 * streamSession - stream session instance.
 * buffer - message send buffer.
 * count - send byte count.
 */
bool streamSessionSend(
	StreamSession streamSession,
	const void* sendBuffer,
	size_t byteCount);
