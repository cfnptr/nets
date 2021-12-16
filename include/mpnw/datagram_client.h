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

/*
 * Datagram client structure (UDP).
 */
typedef struct DatagramClient_T DatagramClient_T;
/*
 * Datagram client instance (UDP).
 */
typedef DatagramClient_T* DatagramClient;

/*
 * Datagram client receive function.
 */
typedef void(*OnDatagramClientReceive)(
	DatagramClient datagramClient,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Create a new datagram client instance (UDP).
 * Returns operation MPNW result.
 *
 * remoteAddress - remote socket address.
 * receiveBufferSize - datagram receive buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 * datagramClient - pointer to the datagramClient value.
 */
MpnwResult createDatagramClient(
	SocketAddress remoteAddress,
	size_t receiveBufferSize,
	OnDatagramClientReceive onReceive,
	void* handle,
	DatagramClient* datagramClient);
/*
 * Destroys datagram client instance.
 * datagramClient - datagram client instance or NULL.
 */
void destroyDatagramClient(DatagramClient datagramClient);

/*
 * Returns datagram client receive buffer size.
 * datagramClient - datagram client instance.
 */
size_t getDatagramClientReceiveBufferSize(DatagramClient datagramClient);
/*
 * Returns datagram client receive function.
 * datagramClient - datagram client instance.
 */
OnDatagramClientReceive getDatagramClientOnReceive(DatagramClient datagramClient);
/*
 * Returns datagram client handle.
 * datagramClient - datagram client instance.
 */
void* getDatagramClientHandle(DatagramClient datagramClient);
/*
 * Returns datagram client socket.
 * datagramClient - datagram client instance.
 */
Socket getDatagramClientSocket(DatagramClient datagramClient);

/*
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * datagramClient - datagram client instance.
 */
bool updateDatagramClient(DatagramClient datagramClient);

/*
 * Send message to the datagram server.
 * Returns true on success.
 *
 * datagramClient - datagram client instance.
 * sendBuffer - datagram send buffer.
 * byteCount - send byte count.
 */
bool datagramClientSend(
	DatagramClient datagramClient,
	const void* sendBuffer,
	size_t byteCount);
