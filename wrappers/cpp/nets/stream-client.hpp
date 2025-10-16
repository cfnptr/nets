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
 * @brief Network stream client functions.
 * @details See the @ref stream-client.h
 */

#pragma once
#include "nets/socket.hpp"
#include "nets/stream-message.hpp"

extern "C"
{
#include "nets/stream-client.h"
}

namespace nets
{

inline static void _onStreamClientConnection(StreamClient_T* streamClient, NetsResult result);
inline static void _onStreamClientDisconnect(StreamClient_T* streamClient, int reason);
inline static int _onStreamClientReceive(StreamClient_T* streamClient, const uint8_t* receiveBuffer, size_t byteCount);
inline static int _onStreamClientDatagram(StreamClient_T* streamClient, const uint8_t* receiveBuffer, size_t byteCount);

/**
 * @brief Stream client instance handle. (TCP)
 * @details See the @ref stream-client.h
 */
class IStreamClient
{
protected:
	StreamClient_T* instance = nullptr;
public:
	IStreamClient(const IStreamClient&) = delete;
	IStreamClient(IStreamClient&& r) noexcept : instance(std::exchange(r.instance, nullptr)) { }

	IStreamClient& operator=(IStreamClient&) = delete;
	IStreamClient& operator=(IStreamClient&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new empty stream client instance. (TCP)
	 */
	IStreamClient() = default;
	/**
	 * @brief Creates a new stream client instance. (TCP)
	 * @details See the @ref createStreamClient().
	 *
	 * @param bufferSize receive data buffer size in bytes
	 * @param timeoutTime server timeout time in seconds
	 * @param sslContext socket SSL context instance or NULL
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	IStreamClient(size_t bufferSize = UINT16_MAX + 1, double timeoutTime = 5.0, SslContextView sslContext = nullptr)
	{
		auto result = createStreamClient(bufferSize, timeoutTime, _onStreamClientConnection, _onStreamClientDisconnect,
			_onStreamClientReceive, _onStreamClientDatagram, this, sslContext.getInstance(), &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys stream client instance.
	 * @details See the @ref destroyStreamClient().
	 */
	void destroy() noexcept { destroyStreamClient(instance); instance = nullptr; }

	/**
	 * @brief Stream client connection result function. (TCP)
	 * @warning This function is called asynchronously from the receive thread!
	 * @param result connection to the server result
	 */
	virtual void onConnectionResult(NetsResult result) = 0;
	/**
	 * @brief Stream client on server disconnect function. (TCP)
	 * @warning This function is called asynchronously from the receive thread!
	 * @param reason server disconnection reason
	 */
	virtual void onDisconnect(int reason) = 0;
	/**
	 * @brief Stream client data receive function. (TCP)
	 * @details Client stops receive thread on this function non zero return result.
	 * @warning This function is called asynchronously from the receive thread!
	 *
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual int onStreamReceive(const uint8_t* receiveBuffer, size_t byteCount) = 0;
	/**
	 * @brief Stream client datagram receive function. (UDP)
	 * @details Client stops receive thread on this function non zero return result.
	 * @warning This function is called asynchronously from the receive thread!
	 *
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual int onDatagramReceive(const uint8_t* receiveBuffer, size_t byteCount) = 0;

	/**
	 * @brief Converts reason value to string.
	 * @param reason target reason value
	 */
	virtual string reasonToString(int reason)
	{
		return reason < NETS_RESULT_COUNT ? netsResultToString(reason) : to_string(reason);
	}

	/*******************************************************************************************************************
	 * @brief Returns stream client handle instance.
	 */
	StreamClient_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns stream client receive buffer size.
	 * @details See the @ref getStreamClientBufferSize().
	 */
	size_t getBufferSize() const noexcept { return getStreamClientBufferSize(instance); }
	/**
	 * @brief Returns stream client server timeout time. (in seconds)
	 * @details See the @ref getStreamClientTimeoutTime().
	 */
	double getTimeoutTime() const noexcept { return getStreamClientTimeoutTime(instance); }
	/**
	 * @brief Returns stream client socket locker.
	 * @details See the @ref getStreamClientBuffer().
	 */
	uint8_t* getBuffer() const noexcept { return getStreamClientBuffer(instance); }

	/**
	 * @brief Returns stream client socket SSL context instance.
	 * @details See the @ref getStreamClientSslContext().
	 */
	SslContextView getSslContext() const noexcept { return getStreamClientSslContext(instance); }
	/**
	 * @brief Sets stream client socket SSL context instance.
	 * @details See the @ref setStreamClientSslContext().
	 * @param sslContext socket SSL context instance or NULL
	 */
	void setSslContext(SslContextView sslContext = nullptr) noexcept
	{
		setStreamClientSslContext(instance, sslContext.getInstance());
	}
	/**
	 * @brief Returns true if stream client use encrypted connection.
	 * @details See the @ref getStreamClientSslContext().
	 */
	bool isSecure() const noexcept { return isStreamClientSecure(instance); }

	/*******************************************************************************************************************
	 * @brief Returns true if stream client receive thread is running.
	 * @details See the @ref isStreamClientRunning().
	 */
	bool isRunning() const noexcept { return isStreamClientRunning(instance); }
	/**
	 * @brief Returns true if stream client is connected to the server.
	 * @details See the @ref isStreamClientConnected().
	 */
	bool isConnected() const noexcept { return isStreamClientConnected(instance); }

	/**
	 * @brief Initiates stream client connection to the server with specified IP address.
	 * @details See the @ref connectStreamClientByAddress().
	 *
	 * @param remoteAddress remote server IP address
	 * @param[in] hostname remote server hostname or NULL
	 * @param noDelay stream socket no delay flag value
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	void connect(SocketAddressView remoteAddress, const char* hostname = nullptr, bool noDelay = true)
	{
		auto result = connectStreamClientByAddress(instance, remoteAddress.getInstance(), hostname, noDelay);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Initiates stream client connection to the server with specified hostname.
	 * @details See the @ref connectStreamClientByHostname().
	 *
	 * @param[in] hostname server hostname string
	 * @param[in] service server service string (port)
	 * @param noDelay stream socket no delay flag value
	 * @param setSNI set SSL server SNI hostname
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	void connect(const char* hostname, const char* service, bool noDelay = true, bool setSNI = true)
	{
		auto result = connectStreamClientByHostname(instance, hostname, service, noDelay, setSNI);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}

	/**
	 * @brief Disconnects stream client from the server.
	 * @details See the @ref disconnectStreamClient().
	 */
	void disconnect() noexcept { disconnectStreamClient(instance); }

	/*******************************************************************************************************************
	 * @brief Updates stream client state.
	 * @details See the @ref streamClientUpdate().
	 *
	 * @param[in] sendBuffer data send buffer
	 * @param byteCount data byte count to send
	 */
	void update() noexcept { return updateStreamClient(instance); }
	/**
	 * @brief Resets stream client server timeout time.
	 * @details See the @ref aliveStreamClient().
	 */
	void alive() noexcept { aliveStreamClient(instance); }

	/**
	 * @brief Sends stream data to the server. (TCP)
	 * @details See the @ref streamClientSend().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult send(const void* data, size_t byteCount) noexcept
	{
		return streamClientSend(instance, data, byteCount);
	}
	/**
	 * @brief Sends stream message to the server. (TCP)
	 * @details See the @ref streamClientSend().
	 * @return The operation @ref NetsResult code.
	 * @param[in] message stream message to send
	 */
	NetsResult send(const OutStreamMessage& message) noexcept
	{
		assert(message.isComplete());
		return streamClientSend(instance, message.getBuffer(), message.getSize());
	}

	/**
	 * @brief Sends datagram to the server. (UDP)
	 * @details See the @ref streamClientSendDatagram().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult sendDatagram(const void* data, size_t byteCount) noexcept
	{
		return streamClientSendDatagram(instance, data, byteCount);
	}
	/**
	 * @brief Sends datagram message to the server. (UDP)
	 * @details See the @ref streamClientSendDatagram().
	 * @return The operation @ref NetsResult code.
	 * @param[in] message datagram message to send
	 */
	NetsResult sendDatagram(const OutStreamMessage& message) noexcept
	{
		assert(message.isComplete());
		return streamClientSendDatagram(instance, message.getBuffer(), message.getSize());
	}
};

inline static void _onStreamClientConnection(StreamClient_T* streamClient, NetsResult result)
{
	auto client = (IStreamClient*)getStreamClientHandle(streamClient);
	client->onConnectionResult(result);
}
inline static void _onStreamClientDisconnect(StreamClient_T* streamClient, int reason)
{
	auto client = (IStreamClient*)getStreamClientHandle(streamClient);
	client->onDisconnect(reason);
}
inline static int _onStreamClientReceive(StreamClient_T* streamClient, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto client = (IStreamClient*)getStreamClientHandle(streamClient);
	return client->onStreamReceive(receiveBuffer, byteCount);
}
inline static int _onStreamClientDatagram(StreamClient_T* streamClient, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto client = (IStreamClient*)getStreamClientHandle(streamClient);
	return client->onDatagramReceive(receiveBuffer, byteCount);
}

} // nets