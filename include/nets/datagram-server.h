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
 * @brief Network datagram server functions. (UDP)
 */

#pragma once
#include "nets/socket.h"

typedef struct DatagramServer_T DatagramServer_T; /**< Datagram server structure. (UDP) */
typedef DatagramServer_T* DatagramServer;         /**< Datagram server instance. (UDP) */

/**
 * @brief Datagram server receive function. (UDP)
 *
 * @param datagramServer datagram server instance
 * @param remoteAddress sender remote socket IP address
 * @param receiveBuffer received data buffer
 * @param byteCount received byte count
 */
typedef void(*OnDatagramServerReceive)(DatagramServer datagramServer, 
	SocketAddress remoteAddress, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Creates a new datagram server instance. (UDP)
 * @return The operation @ref NetsResult code.
 *
 * @param socketFamily local socket IP address family
 * @param service local IP address service string (port)
 * @param bufferSize receive data buffer size in bytes
 * @param[in] onReceive on datagram receive function.
 * @param[in] handle receive function argument or NULL
 * @param datagramServer pointer to the datagram server instance
 */
NetsResult createDatagramServer(SocketFamily socketFamily, const char* service, size_t bufferSize, 
	OnDatagramServerReceive onReceive, void* handle, DatagramServer* datagramServer);
/**
 * @brief Destroys datagram server instance. (UDP)
 * @param datagramServer target datagram server instance or NULL
 */
void destroyDatagramServer(DatagramServer datagramServer);

/***********************************************************************************************************************
 * @brief Returns datagram server receive buffer size in bytes.
 * @param datagramServer target datagram server instance
 */
size_t getDatagramServerBufferSize(DatagramServer datagramServer);
/**
 * @brief Returns datagram server receive data buffer.
 * @param datagramServer target datagram server instance
 */
uint8_t* getDatagramServerBuffer(DatagramServer datagramServer);
/**
 * @brief Returns datagram server receive function.
 * @param datagramServer target datagram server instance
 */
OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer datagramServer);
/**
 * @brief Returns datagram server handle.
 * @param datagramServer target datagram server instance
 */
void* getDatagramServerHandle(DatagramServer datagramServer);
/**
 * @brief Returns datagram server socket instance.
 * @param datagramServer target datagram server instance
 */
Socket getDatagramServerSocket(DatagramServer datagramServer);
/**
 * @brief Receives pending datagram messages.
 * @return The operation @ref NetsResult code.
 * @param datagramServer target datagram server instance
 */
NetsResult updateDatagramServer(DatagramServer datagramServer);

/**
 * @brief Sends datagram message to the specified remote IP address.
 * @return The operation @ref NetsResult code.
 *
 * @param datagramServer target datagram server instance
 * @param[in] data send data buffer
 * @param byteCount message byte count to send
 * @param remoteAddress destination remote socket IP address
 */
NetsResult datagramServerSend(DatagramServer datagramServer, 
	const void* data, size_t byteCount, SocketAddress remoteAddress);