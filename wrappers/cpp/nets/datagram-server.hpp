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
 * @brief Network datagram server functions.
 * @details See the @ref datagram-server.h
 */

#pragma once
#include "nets/socket.hpp"
#include "nets/stream-message.hpp"

extern "C"
{
#include "nets/datagram-server.h"
}

namespace nets
{

inline static void _onDatagramServerReceive(DatagramServer_T* datagramServer, 
	SocketAddress_T* remoteAddress, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Datagram server instance handle. (TCP)
 * @details See the @ref datagram-server.h
 */
class IDatagramServer
{
protected:
	DatagramServer_T* instance = nullptr;
public:
	IDatagramServer(const IDatagramServer&) = delete;
	IDatagramServer(IDatagramServer&& r) noexcept : instance(std::exchange(r.instance, nullptr)) { }

	IDatagramServer& operator=(IDatagramServer&) = delete;
	IDatagramServer& operator=(IDatagramServer&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new datagram server instance. (TCP)
	 * @details See the @ref createDatagramServer().
	 *
	 * @param socketFamily local socket IP address family
	 * @param service local IP address service string (port)
	 * @param bufferSize receive data buffer size in bytes
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	IDatagramServer(SocketFamily socketFamily, const char* service, size_t bufferSize = UINT16_MAX + 1)
	{
		auto result = createDatagramServer(socketFamily, service, 
			bufferSize, _onDatagramServerReceive, this, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys datagram server instance.
	 * @details See the @ref destroyDatagramServer().
	 */
	void destroy() noexcept { destroyDatagramServer(instance); instance = nullptr; }

	/**
	 * @brief Datagram server receive function. (UDP)
	 *
	 * @param remoteAddress sender remote socket address
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual void onDatagramReceive(SocketAddressView remoteAddress, const uint8_t* receiveBuffer, size_t byteCount) = 0;

	/*******************************************************************************************************************
	 * @brief Returns datagram server handle instance.
	 */
	DatagramServer_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns datagram server receive buffer size in bytes.
	 * @details See the @ref getDatagramServerBufferSize().
	 */
	size_t getBufferSize() const noexcept { return getDatagramServerBufferSize(instance); }
	/**
	 * @brief Returns datagram server receive data buffer.
	 * @details See the @ref getDatagramServerBuffer().
	 */
	uint8_t* getBuffer() const noexcept { return getDatagramServerBuffer(instance); }
	/**
	 * @brief Returns datagram server socket instance.
	 * @details See the @ref getDatagramServerSocket().
	 */
	SocketView getSocket() const noexcept { return getDatagramServerSocket(instance); }

	/**
	 * @brief Receives pending datagram messages. (Non blocking)
	 * @details See the @ref updateDatagramServer().
	 * @return The operation @ref NetsResult code.
	 */
	NetsResult update() noexcept { return updateDatagramServer(instance); }

	/**
	 * @brief Sends datagram to the specified remote address. (UDP)
	 * @details See the @ref datagramServerSend().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 * @param remoteAddress recipient remote socket IP address
	 */
	NetsResult send(const void* data, size_t byteCount, SocketAddressView remoteAddress) noexcept
	{
		return datagramServerSend(instance, data, byteCount, remoteAddress.getInstance());
	}
	/**
	 * @brief Sends datagram to the specified remote address. (UDP)
	 * @details See the @ref datagramServerSend().
	 * @return The operation @ref NetsResult code.
	 * @param[in] message datagram message to send
	 * @param remoteAddress recipient remote socket IP address
	 */
	NetsResult send(const OutStreamMessage& message, SocketAddressView remoteAddress) noexcept
	{
		assert(message.isComplete());
		return datagramServerSend(instance, message.getBuffer(), message.getSize(), remoteAddress.getInstance());
	}
};

inline static void _onDatagramServerReceive(DatagramServer_T* datagramServer, 
	SocketAddress_T* remoteAddress, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto server = (IDatagramServer*)getDatagramServerHandle(datagramServer);
	return server->onDatagramReceive(remoteAddress, receiveBuffer, byteCount);
}

} // namespace nets