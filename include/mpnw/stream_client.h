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
 * Stream client structure. (TCP)
*/
typedef struct StreamClient_T StreamClient_T;
/*
 * Stream client instance. (TCP)
*/
typedef StreamClient_T* StreamClient;

/*
 * Stream client receive function.
 */
typedef void(*OnStreamClientReceive)(
	StreamClient streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Create a new stream client instance (TCP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * receiveBufferSize - data receive buffer size.
 * onReceive - data receive function.
 * handle - receive function argument.
 * sslContext - SSL context instance or NULL.
 * streamClient - pointer to the stream client value.
 */
MpnwResult createStreamClient(
	AddressFamily addressFamily,
	size_t receiveBufferSize,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* streamClient);
/*
 * Destroys stream client instance.
 * streamClient - stream client instance or NULL.
 */
void destroyStreamClient(StreamClient streamClient);

/*
* Returns stream client receive buffer size.
* streamClient - stream client instance.
*/
size_t getStreamClientReceiveBufferSize(StreamClient streamClient);
/*
* Returns stream client receive function.
* streamClient - stream client instance.
*/
OnStreamClientReceive getStreamClientOnReceive(StreamClient streamClient);
/*
 * Returns stream client handle.
 * streamClient - stream client instance.
 */
void* getStreamClientHandle(StreamClient streamClient);
/*
 * Returns stream client socket.
 * streamClient - stream client instance.
 */
Socket getStreamClientSocket(StreamClient streamClient);

/*
 * Connect stream client to the server.
 * Returns true on success.
 *
 * streamClient - stream client instance.
 * remoteAddress - remote socket address.
 * timeoutTime - time out time (ms).
 */
bool connectStreamClient(
	StreamClient streamClient,
	SocketAddress remoteAddress,
	double timeoutTime);

/*
 * Receive buffered datagrams.
 * Returns true if any data is received.
 *
 * streamClient - stream client instance.
 */
bool updateStreamClient(StreamClient streamClient);

/*
 * Send data to the server.
 * Returns true on success.
 *
 * streamClient - stream client instance.
 * sendBuffer - data send buffer.
 * byteCount - send byte count.
 */
bool streamClientSend(
	StreamClient streamClient,
	const void* sendBuffer,
	size_t byteCount);

/*
 * Send stream message to the server.
 * Returns true on success.
 *
 * streamClient - stream client instance.
 * sendBuffer - send stream message.
 */
bool streamClientSendMessage(
	StreamClient streamClient,
	StreamMessage streamMessage);
