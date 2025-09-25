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
 * @brief Network stream client functions. (TCP)
 */

#pragma once
#include "nets/socket.h"

typedef struct StreamClient_T StreamClient_T; /**< Stream client structure. (TCP) */
typedef StreamClient_T* StreamClient;         /**< Stream client instance. (TCP) */

/**
 * @brief Stream client receive function. (TCP)
 *
 * @param streamClient stream client instance
 * @param[in] receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef void(*OnStreamClientReceive)(StreamClient streamClient, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Creates a new stream client instance. (TCP)
 * @return The operation @ref NetsResult code.
 *
 * @param bufferSize receive data buffer size in bytes
 * @param timeoutTime server timeout time in seconds
 * @param[in] onReceive on data receive function
 * @param[in] handle receive function argument or NULL
 * @param sslContext socket SSL context instance or NULL
 * @param[out] streamClient pointer to the stream client instance
 */
NetsResult createStreamClient(size_t bufferSize, double timeoutTime, OnStreamClientReceive onReceive,
	void* handle, SslContext sslContext, StreamClient* streamClient);
/**
 * @brief Destroys stream client instance. (TCP)
 * @param streamClient target stream client instance or NULL
 */
void destroyStreamClient(StreamClient streamClient);

/***********************************************************************************************************************
 * @brief Returns stream client receive buffer size in bytes.
 * @param streamClient target stream client instance
 */
size_t getStreamClientBufferSize(StreamClient streamClient);
/**
 * @brief Returns stream client receive function.
 * @param streamClient target stream client instance
 */
OnStreamClientReceive getStreamClientOnReceive(StreamClient streamClient);
/**
 * @brief Returns stream client handle.
 * @param streamClient target stream client instance
 */
void* getStreamClientHandle(StreamClient streamClient);
/**
 * @brief Returns stream client data buffer.
 * @param streamClient target stream client instance
 */
uint8_t* getStreamClientBuffer(StreamClient streamClient);
/**
 * @brief Returns stream client socket instance.
 * @param streamClient target stream client instance
 */
Socket getStreamClientSocket(StreamClient streamClient);

/**
 * @brief Returns stream client server timeout time. (in seconds)
 * @param streamClient target stream client instance
 */
double getStreamClientTimeoutTime(StreamClient streamClient);
/**
 * @brief Sets stream client server timeout time. (in seconds)
 *
 * @param streamClient target stream client instance
 * @param timeoutTime server timeout time in seconds
 */
void setStreamClientTimeoutTime(StreamClient streamClient, double timeoutTime);

/**
 * @brief Returns stream client socket SSL context instance.
 * @param streamClient target stream client instance
 */
SslContext getStreamClientSslContext(StreamClient streamClient);
/**
 * @brief Sets stream client socket SSL context instance.
 *
 * @param streamClient target stream client instance
 * @param sslContext socket SSL context instance or NULL
 */
void setStreamClientSslContext(StreamClient streamClient, SslContext sslContext);

/***********************************************************************************************************************
 * @brief Returns true if stream client has been connected.
 * @param streamClient target stream client instance
 */
bool isStreamClientConnected(StreamClient streamClient);
/**
 * @brief Connects stream client to the server with specified IP address.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param remoteAddress remote server IP address
 * @param[in] hostname remote server hostname or NULL
 */
NetsResult connectAddressStreamClient(StreamClient streamClient, SocketAddress remoteAddress, const char* hostname);
/**
 * @brief Connects stream client to the server with specified hostname.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param[in] hostname server hostname string
 * @param[in] service server service string (port)
 * @param setSNI set SSL server SNI hostname
 */
NetsResult connectHostnameStreamClient(StreamClient streamClient, 
	const char* hostname, const char* service, bool setSNI);
/**
 * @brief Disconnects stream client from the server.
 * @param streamClient target stream client instance
 */
void disconnectStreamClient(StreamClient streamClient);

/**
 * @brief Receives pending stream data.
 * @return The operation @ref NetsResult code.
 * @param streamClient target stream client instance
 */
NetsResult updateStreamClient(StreamClient streamClient);
/**
 * @brief Resets stream client response timeout counter.
 * @param streamClient target stream client instance
 */
void resetStreamClientTimeout(StreamClient streamClient);

/**
 * @brief Sends stream data to the server.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param[in] sendBuffer data send buffer
 * @param byteCount data byte count to send
 */
NetsResult streamClientSend(StreamClient streamClient, const void* sendBuffer, size_t byteCount);

/**
 * @brief Sends stream message to the server.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param streamMessage stream message to send
 */
NetsResult streamClientSendMessage(StreamClient streamClient, StreamMessage streamMessage);