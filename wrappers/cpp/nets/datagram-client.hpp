// Copyright 2021-2025 Nikita Fediuchin. All rights reserved.
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
 * @brief Network datagram client functions.
 * @details See the @ref datagram-client.h
 */

#pragma once
#include "nets/socket.hpp"
#include "nets/stream-message.hpp"

extern "C"
{
#include "nets/datagram-client.h"
}

namespace nets
{

inline static void _onDatagramClientReceive(DatagramClient_T* datagramClient, 
	const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Datagram client instance handle. (UDP)
 * @details See the @ref datagram-client.h
 */
class IDatagramClient
{
protected:
	DatagramClient_T* instance = nullptr;
public:
	IDatagramClient(const IDatagramClient&) = delete;
	IDatagramClient(IDatagramClient&& r) noexcept : instance(std::exchange(r.instance, nullptr)) { }

	IDatagramClient& operator=(IDatagramClient&) = delete;
	IDatagramClient& operator=(IDatagramClient&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new empty datagram client instance. (UDP)
	 */
	IDatagramClient() = default;
	/**
	 * @brief Creates a new datagram client instance. (TCP)
	 * @details See the @ref createDatagramClient().
	 *
	 * @param remoteAddress remote socket IP address
	 * @param sslContext socket SSL context instance or NULL
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	IDatagramClient(SocketAddressView remoteAddress, size_t bufferSize)
	{
		auto result = createDatagramClient(remoteAddress.getInstance(), 
			bufferSize, _onDatagramClientReceive, this, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys datagram client instance.
	 * @details See the @ref destroyDatagramClient().
	 */
	void destroy() noexcept { destroyDatagramClient(instance); instance = nullptr; }

	/**
	 * @brief Datagram client receive function. (UDP)
	 *
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual void onDatagramReceive(const uint8_t* receiveBuffer, size_t byteCount) = 0;

	/*******************************************************************************************************************
	 * @brief Returns datagram client handle instance.
	 */
	DatagramClient_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns datagram client receive buffer size.
	 * @details See the @ref getDatagramClientBufferSize().
	 */
	size_t getBufferSize() const noexcept { return getDatagramClientBufferSize(instance); }
	/**
	 * @brief Returns datagram client receive data buffer.
	 * @details See the @ref getDatagramClientBuffer().
	 */
	uint8_t* getBuffer() const noexcept { return getDatagramClientBuffer(instance); }

	/**
	 * @brief Receives pending datagram messages. (Non blocking)
	 * @details See the @ref updateDatagramClient().
	 * @return The operation @ref NetsResult code.
	 */
	NetsResult update() noexcept { return updateDatagramClient(instance); }

	/**
	 * @brief Sends datagram to the server.
	 * @details See the @ref datagramClientSend().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult send(const void* data, size_t byteCount) noexcept
	{
		return datagramClientSend(instance, data, byteCount);
	}
	/**
	 * @brief Sends datagram message to the server.
	 * @details See the @ref datagramClientSend().
	 * @return The operation @ref NetsResult code.
	 * @param[in] message datagram message to send
	 */
	NetsResult send(const OutStreamMessage& message) noexcept
	{
		assert(message.isComplete());
		return datagramClientSend(instance, message.getBuffer(), message.getSize());
	}
};

inline static void _onDatagramClientReceive(DatagramClient_T* datagramClient, 
	const uint8_t* receiveBuffer, size_t byteCount)
{
	auto client = (IDatagramClient*)getDatagramClientHandle(datagramClient);
	client->onDatagramReceive(receiveBuffer, byteCount);
}

} // nets