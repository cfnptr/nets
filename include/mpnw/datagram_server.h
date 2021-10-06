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

/* Datagram server instance handle (UDP) */
typedef struct DatagramServer* DatagramServer;

/* Datagram server receive function */
typedef void(*OnDatagramServerReceive)(
	DatagramServer datagramServer,
	SocketAddress socketAddress,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Creates a new datagram server (UDP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * receiveBufferSize - datagram receive buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 */
MpnwResult createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t receiveBufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* datagramServer);

/*
 * Destroy datagram server instance.
 * datagramServer - datagram server instance or NULL.
 */
void destroyDatagramServer(DatagramServer datagramServer);

/*
 * Returns datagram server receive buffer size.
 * datagramServer - datagram server instance.
 */
size_t getDatagramServerReceiveBufferSize(DatagramServer datagramServer);

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
 * Returns true if datagram received.
 *
 * datagramServer - datagram server instance.
 */
bool updateDatagramServer(DatagramServer datagramServer);

/*
 * Send message to the specified address.
 * Returns true on success.
 *
 * datagramServer - datagram server instance.
 * sendBuffer - datagram send buffer.
 * byteCount - send byte count.
 * socketAddress - destination socket address.
 */
bool datagramServerSend(
	DatagramServer datagramServer,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress socketAddress);
