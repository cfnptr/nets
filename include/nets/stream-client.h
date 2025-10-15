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
 * @brief Stream client connection result function. (TCP)
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamClient stream client instance
 * @param result connection to the server result
 */
typedef void(*OnStreamClientConnection)(StreamClient streamClient, NetsResult result);
/**
 * @brief Stream client on server disconnect function. (TCP)
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamClient stream client instance
 * @param reason server disconnection reason
 */
typedef void(*OnStreamClientDisconnect)(StreamClient streamClient, int reason);
/**
 * @brief Stream client data receive function. (TCP)
 * @details Client stops receive thread on this function non zero return result.
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamClient stream client instance
 * @param[in] receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef int(*OnStreamClientReceive)(StreamClient streamClient, const uint8_t* receiveBuffer, size_t byteCount);
/**
 * @brief Stream client datagram receive function. (UDP)
 * @details Client stops receive thread on this function non zero return result.
 * @warning This function is called asynchronously from the receive thread!
 *
 * @param streamClient stream client instance
 * @param[in] receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef int(*OnStreamClientDatagram)(StreamClient streamClient, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Creates a new stream client instance. (TCP)
 * @return The operation @ref NetsResult code.
 *
 * @param bufferSize receive data buffer size in bytes
 * @param timeoutTime server timeout time in seconds
 * @param[in] onConnection on connection result function
 * @param[in] onDisconnect on server disconnect function
 * @param[in] onReceive on data receive function
 * @param[in] onDatagram on datagrtam receive function or NULL
 * @param[in] handle receive function argument or NULL
 * @param sslContext socket SSL context instance or NULL
 * @param[out] streamClient pointer to the stream client instance
 */
NetsResult createStreamClient(size_t bufferSize, double timeoutTime, OnStreamClientConnection onConnection,
	OnStreamClientDisconnect onDisconnect, OnStreamClientReceive onReceive, OnStreamClientDatagram onDatagram, 
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
 * @brief Returns stream client server timeout time. (in seconds)
 * @param streamClient target stream client instance
 */
double getStreamClientTimeoutTime(StreamClient streamClient);
/**
 * @brief Returns stream client connection result function.
 * @param streamClient target stream client instance
 */
OnStreamClientConnection getStreamClientOnConnection(StreamClient streamClient);
/**
 * @brief Returns stream client data receive function.
 * @param streamClient target stream client instance
 */
OnStreamClientReceive getStreamClientOnReceive(StreamClient streamClient);
/**
 * @brief Returns stream client datagram receive function.
 * @param streamClient target stream client instance
 */
OnStreamClientDatagram getStreamClientOnDatagram(StreamClient streamClient);
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
/**
 * @brief Returns true if stream client use encrypted connection.
 * @param streamClient target stream client instance
 */
bool isStreamClientSecure(StreamClient streamClient);

/***********************************************************************************************************************
 * @brief Returns true if stream client receive thread is running. (MT-Safe)
 * @param streamClient target stream client instance
 */
bool isStreamClientRunning(StreamClient streamClient);
/**
 * @brief Returns true if stream client is connected to the server. (MT-Safe)
 * @param streamClient target stream client instance
 */
bool isStreamClientConnected(StreamClient streamClient);

/**
 * @brief Initiates stream client connection to the server with specified IP address.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param remoteAddress remote server IP address
 * @param[in] hostname remote server hostname or NULL
 * @param noDelay stream socket no delay flag value
 */
NetsResult connectStreamClientByAddress(StreamClient streamClient, 
	SocketAddress remoteAddress, const char* hostname, bool noDelay);
/**
 * @brief Initiates stream client connection to the server with specified hostname and service.
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param[in] hostname server hostname string
 * @param[in] service server service string (port)
 * @param noDelay stream socket no delay flag value
 * @param setSNI set SSL server SNI hostname
 */
NetsResult connectStreamClientByHostname(StreamClient streamClient, 
	const char* hostname, const char* service, bool noDelay, bool setSNI);

/**
 * @brief Disconnects stream client from the server.
 * @param streamClient target stream client instance
 */
void disconnectStreamClient(StreamClient streamClient);

/**
 * @brief Updates stream client state.
 * @param streamClient target stream client instance
 */
void updateStreamClient(StreamClient streamClient);

/**
 * @brief Sends stream data to the server. (TCP)
 * @details Internally synchronized. (MT-Safe)
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param[in] data data send buffer
 * @param byteCount data byte count to send
 */
NetsResult streamClientSend(StreamClient streamClient, const void* data, size_t byteCount);
/**
 * @brief Sends datagram to the server. (UDP)
 * @details Internally synchronized. (MT-Safe)
 * @return The operation @ref NetsResult code.
 *
 * @param streamClient target stream client instance
 * @param[in] data send data buffer
 * @param byteCount data byte count to send
 */
NetsResult streamClientSendDatagram(StreamClient streamClient, const void* data, size_t byteCount);