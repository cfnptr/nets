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

#pragma once
#include "mpnw/socket.h"

/*
 * Datagram server structure. (UDP)
 */
typedef struct DatagramServer_T DatagramServer_T;
/*
 * Datagram server instance. (UDP)
 */
typedef DatagramServer_T* DatagramServer;

/*
 * Datagram server receive function.
 *
 * datagramServer - datagram server instance.
 * remoteAddress - remote address instance.
 * receiveBuffer - receive buffer size.
 * byteCount - received byte count.
 */
typedef void(*OnDatagramServerReceive)(
	DatagramServer datagramServer,
	SocketAddress remoteAddress,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Create a new datagram server (UDP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * bufferSize - data buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 * datagramServer - pointer to the datagram server.
 */
MpnwResult createDatagramServer(
	AddressFamily addressFamily,
	const char* service,
	size_t bufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* datagramServer);
/*
 * Destroys datagram server instance.
 * datagramServer - datagram server instance or NULL.
 */
void destroyDatagramServer(DatagramServer datagramServer);

/*
 * Returns datagram server data buffer size.
 * datagramServer - datagram server instance.
 */
size_t getDatagramServerBufferSize(DatagramServer datagramServer);
/*
 * Returns datagram server receive function.
 * datagramServer - datagram server instance.
 */
OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer datagramServer);
/*
 * Returns datagram server handle.
 * datagramServer - datagram server instance.
 */
void* getDatagramServerHandle(DatagramServer datagramServer);
/*
 * Returns datagram server socket.
 * datagramServer - datagram server instance.
 */
Socket getDatagramServerSocket(DatagramServer datagramServer);
/*
 * Receive buffered datagrams.
 * Returns operation MPNW result.
 *
 * datagramServer - datagram server instance.
 */
MpnwResult updateDatagramServer(DatagramServer datagramServer);

/*
 * Send message to the specified address.
 * Returns operation MPNW result.
 *
 * datagramServer - datagram server instance.
 * sendBuffer - datagram send buffer.
 * byteCount - send byte count.
 * remoteAddress - destination socket address.
 */
MpnwResult datagramServerSend(
	DatagramServer datagramServer,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress remoteAddress);
