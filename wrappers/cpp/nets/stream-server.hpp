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
 * @brief Network stream server functions.
 * @details See the @ref stream-server.h
 */

#pragma once
#include "nets/socket.hpp"

extern "C"
{
#include "nets/stream-server.h"
}

namespace nets
{

/**
 * @brief Stream session instance view.
 * @details See the @ref stream-server.h
 */
struct StreamSessionView final
{
private:
	StreamSession_T* instance = nullptr;
public:
	/**
	 * @brief Creates a new stream stream session handle.
	 * @param[in] instance target stream session instance
	 */
	StreamSessionView(StreamSession_T* instance) : instance(instance) { }

	/**
	 * @brief Returns stream session view instance.
	 */
	StreamSession_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns stream session socket instance.
	 * @details See the @ref getStreamSessionSocket().
	 */
	SocketView getSocket() const noexcept { return SocketView(getStreamSessionSocket(instance)); }
	/**
	 * @brief Returns stream session remote IP address instance.
	 * @details See the @ref getStreamSessionRemoteAddress().
	 */
	SocketAddressView getRemoteAddress() const noexcept
	{
		return SocketAddressView(getStreamSessionRemoteAddress(instance));
	}
	/**
	 * @brief Returns stream session handle.
	 * @details See the @ref createStreamServer().
	 */
	void* getHandle() const noexcept { return getStreamSessionHandle(instance); }
};

inline static bool _onStreamSessionCreate(StreamServer_T* streamServer, StreamSession_T* streamSession, void** handle);
inline static void _onStreamSessionDestroy(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, NetsResult netsResult);
inline static NetsResult _onStreamSessionReceive(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, const uint8_t* receiveBuffer, size_t byteCount);

/***********************************************************************************************************************
 * @brief Stream server instance handle. (TCP)
 * @details See the @ref stream-server.h
 */
struct IStreamServer
{
protected:
	StreamServer_T* instance = nullptr;
public:
	IStreamServer(const IStreamServer&) = delete;
	IStreamServer(IStreamServer&& r) noexcept : instance(std::exchange(r.instance, nullptr)) { }

	IStreamServer& operator=(IStreamServer&) = delete;
	IStreamServer& operator=(IStreamServer&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new stream server instance. (TCP)
	 * @details See the @ref createStreamServer().
	 *
	 * @param socketFamily local socket IP address family
	 * @param[in] service local IP address service string (port)
	 * @param sessionBufferSize session buffer size
	 * @param connectionQueueSize pending connections queue size
	 * @param receiveBufferSize receive data buffer size in bytes
	 * @param timeoutTime session timeout time in seconds
	 * @param sslContext socket SSL context instance or NULL
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	IStreamServer(SocketFamily socketFamily, const char* service, size_t sessionBufferSize, size_t connectionQueueSize, 
		size_t receiveBufferSize, double timeoutTime, SslContextView sslContext = SslContextView(nullptr))
	{
		auto result = createStreamServer(socketFamily, service, sessionBufferSize, connectionQueueSize, 
			receiveBufferSize, timeoutTime, _onStreamSessionCreate, _onStreamSessionDestroy,
			_onStreamSessionReceive, this, sslContext.getInstance(), &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys socket IP address instance.
	 * @details See the @ref destroySocketAddress().
	 */
	~IStreamServer() { destroyStreamServer(instance); }

	/**
	 * @brief Stream session create function. (TCP)
	 * @note Server destroys session on this function false return result.
	 *
	 * @param streamSession a new accepted stream session instance
	 * @param[out] handle pointer to the custom session handle
	 */
	virtual bool onSessionCreate(StreamSessionView streamSession, void*& handle) = 0;
	/**
	 * @brief Stream session destroy function. (TCP)
	 *
	 * @param streamSession stream session instance
	 * @param reason session destruction reason
	 */
	virtual void onSessionDestroy(StreamSessionView streamSession, NetsResult reason) = 0;
	/**
	 * @brief Stream session receive function. (TCP)
	 * @note Server destroys session on this function failure return result.
	 *
	 * @param streamSession stream session instance
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual NetsResult onSessionReceive(StreamSessionView streamSession, const uint8_t* receiveBuffer, size_t byteCount);

	/*******************************************************************************************************************
	 * @brief Returns stream server handle instance.
	 */
	StreamServer_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns stream server session buffer size.
	 * @details See the @ref getStreamServerSessionBufferSize().
	 */
	size_t getSessionBufferSize() const noexcept { return getStreamServerSessionBufferSize(instance); }
	/**
	 * @brief Returns stream server receive buffer size in bytes.
	 * @details See the @ref getStreamServerReceiveBufferSize().
	 */
	size_t getReceiveBufferSize() const noexcept { return getStreamServerReceiveBufferSize(instance); }
	/**
	 * @brief Returns stream server session timeout time. (in seconds)
	 * @details See the @ref getStreamServerTimeoutTime().
	 */
	double getTimeoutTime() const noexcept { return getStreamServerTimeoutTime(instance); }
	/**
	 * @brief Returns stream server receive data buffer.
	 * @details See the @ref getStreamServerReceiveBuffer().
	 */
	uint8_t* getReceiveBuffer() const noexcept { return getStreamServerReceiveBuffer(instance); }
	/**
	 * @brief Returns stream server socket instance.
	 * @details See the @ref getStreamServerSocket().
	 */
	SocketView getSocket() const noexcept { return SocketView(getStreamServerSocket(instance)); }
};

inline static bool _onStreamSessionCreate(StreamServer_T* streamServer, StreamSession_T* streamSession, void** handle)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	return server->onSessionCreate(StreamSessionView(streamSession), *handle);
}
inline static void _onStreamSessionDestroy(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, NetsResult netsResult)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	server->onSessionDestroy(StreamSessionView(streamSession), netsResult);
}
inline static NetsResult _onStreamSessionReceive(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	return server->onSessionReceive(StreamSessionView(streamSession), receiveBuffer, byteCount);
}

} // nets