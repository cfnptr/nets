// Copyright 2020-2026 Nikita Fediuchin. All rights reserved.
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
 * @brief Network datagram client functions. (UDP)
 */

#pragma once
#include "nets/socket.h"

typedef struct DatagramClient_T DatagramClient_T; /**< Datagram client structure (UDP). */
typedef DatagramClient_T* DatagramClient;         /**< Datagram client instance (UDP). */

/**
 * @brief Datagram client receive function. (UDP)
 *
 * @param datagramClient datagram client instance
 * @param[in] receiveBuffer receive data buffer
 * @param byteCount received byte count.
 */
typedef void(*OnDatagramClientReceive)(DatagramClient datagramClient, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Creates a new datagram client instance. (UDP)
 * @return The operation @ref NetsResult code.
 *
 * @param remoteAddress remote socket IP address
 * @param bufferSize receive data buffer size in bytes
 * @param[in] onReceive on datagram receive function
 * @param[in] handle receive function argument or NULL
 * @param datagramClient pointer to the datagram client instance
 */
NetsResult createDatagramClient(SocketAddress remoteAddress, size_t bufferSize, 
	OnDatagramClientReceive onReceive, void* handle, DatagramClient* datagramClient);
/**
 * @brief Destroys datagram client instance. (UDP)
 * @param datagramClient target datagram client instance or NULL
 */
void destroyDatagramClient(DatagramClient datagramClient);

/***********************************************************************************************************************
 * @brief Returns datagram client receive buffer size in bytes.
 * @param datagramClient target datagram client instance
 */
size_t getDatagramClientBufferSize(DatagramClient datagramClient);
/**
 * @brief Returns datagram client receive data buffer.
 * @param datagramClient target datagram client instance
 */
uint8_t* getDatagramClientBuffer(DatagramClient datagramClient);
/**
 * @brief Returns datagram client receive function.
 * @param datagramClient target datagram client instance
 */
OnDatagramClientReceive getDatagramClientOnReceive(DatagramClient datagramClient);
/**
 * @brief Returns datagram client handle.
 * @param datagramClient target datagram client instance
 */
void* getDatagramClientHandle(DatagramClient datagramClient);
/**
 * @brief Returns datagram client socket instance.
 * @param datagramClient target datagram client instance
 */
Socket getDatagramClientSocket(DatagramClient datagramClient);

/**
 * @brief Receives pending datagram messages.
 * @return The operation @ref NetsResult code.
 * @param datagramClient target datagram client instance
 */
NetsResult updateDatagramClient(DatagramClient datagramClient);

/**
 * @brief Sends datagram message to the server.
 * @return The operation @ref NetsResult code.
 *
 * @param datagramClient target datagram client instance
 * @param data send data buffer
 * @param byteCount data byte count to send
 */
NetsResult datagramClientSend(DatagramClient datagramClient, const void* data, size_t byteCount);