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
#include "nets/stream-message.hpp"

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
	StreamSessionView(StreamSession_T* instance) noexcept : instance(instance) { }

	/**
	 * @brief Returns stream session view instance.
	 */
	StreamSession_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns stream session socket instance.
	 * @details See the @ref getStreamSessionSocket().
	 */
	SocketView getSocket() const noexcept { return getStreamSessionSocket(instance); }
	/**
	 * @brief Returns stream session remote IP address instance.
	 * @details See the @ref getStreamSessionRemoteAddress().
	 */
	SocketAddressView getRemoteAddress() const noexcept { return getStreamSessionRemoteAddress(instance); }
	/**
	 * @brief Returns stream session handle.
	 * @warning Handle may be null if socket is not fully connected!
	 * @details See the @ref createStreamServer().
	 */
	void* getHandle() const noexcept { return getStreamSessionHandle(instance); }

	/**
	 * @brief Returns stream session IP address and port string.
	 */
	string getAddress() const
	{
		auto remoteAddress = getRemoteAddress();
		string ip, port; remoteAddress.getHostService(ip, port);
		if (ip.empty() || port.empty())
			return "";
		if (remoteAddress.isMappedV4() && ip.size() > 7)
			ip = string(ip.c_str() + 7, ip.size() - 7);
		ip.reserve(ip.size() + port.size() + 1);
		ip += ":"; ip += port;
		return ip;
	}

	/**
	 * @brief Sends stream data to the specified session. (TCP)
	 * @details See the @ref streamSessionSend().
	 * @warning You should lock sessions before sending messages!
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult send(const void* data, size_t byteCount) noexcept
	{
		return streamSessionSend(instance, data, byteCount);
	}
	/**
	 * @brief Sends stream message to the specified session. (TCP)
	 * @details See the @ref streamSessionSend().
	 * @warning You should lock sessions before sending messages!
	 * @return The operation @ref NetsResult code.
	 * @param[in] message stream message to send
	 */
	NetsResult send(const OutStreamMessage& message) noexcept
	{
		assert(message.isComplete());
		return streamSessionSend(instance, message.getBuffer(), message.getSize());
	}

	/**
	 * @brief Resets stream session timeout time.
	 * @details See the @ref aliveStreamSession().
	 * @warning You should lock sessions before aliving!
	 */
	void alive() noexcept { aliveStreamSession(instance); }

	/**
	 * @brief Shutdowns part of the full-duplex socket connection.
	 * @details See the @ref shutdownStreamSession().
	 * @warning You should lock sessions before shutting down!
	 * @return The operation @ref NetsResult code.
	 * @param shutdown socket connection shutdown mode
	 */
	NetsResult shutdown(SocketShutdown shutdown = RECEIVE_SEND_SOCKET_SHUTDOWN) noexcept
	{
		return shutdownStreamSession(instance, shutdown);
	}
};

inline static void* _onStreamSessionCreate(StreamServer_T* streamServer, StreamSession_T* streamSession);
inline static void _onStreamSessionDestroy(StreamServer_T* streamServer, StreamSession_T* streamSession, int reason);
inline static int _onStreamSessionReceive(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, const uint8_t* receiveBuffer, size_t byteCount);
inline static void _onStreamServerDatagram(StreamServer_T* streamServer, 
	SocketAddress_T* remoteAddress, const uint8_t* receiveBuffer, size_t byteCount);

/***********************************************************************************************************************
 * @brief Stream server instance handle. (TCP)
 * @details See the @ref stream-server.h
 */
class IStreamServer
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
	 * @param sessionBufferSize maximum stream session count
	 * @param connectionQueueSize pending connections queue size
	 * @param receiveBufferSize receive data buffer size in bytes
	 * @param timeoutTime session timeout time in seconds
	 * @param sslContext socket SSL context instance or NULL
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	IStreamServer(SocketFamily socketFamily, const char* service, size_t sessionBufferSize = 512, 
		size_t connectionQueueSize = 256, size_t receiveBufferSize = UINT16_MAX + 1, 
		double timeoutTime = 5.0, SslContextView sslContext = nullptr)
	{
		auto result = createStreamServer(socketFamily, service, sessionBufferSize, connectionQueueSize, 
			receiveBufferSize, timeoutTime, _onStreamSessionCreate, _onStreamSessionDestroy,
			_onStreamSessionReceive, _onStreamServerDatagram, this, sslContext.getInstance(), &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys stream server instance.
	 * @details See the @ref destroyStreamServer().
	 */
	void destroy() noexcept { destroyStreamServer(instance); instance = nullptr; }

	/**
	 * @brief Stream session create function. (TCP)
	 * @warning This function is called asynchronously from the receive thread!
	 * @return Custom stream session handle on success, otherwise NULL.
	 *
	 * @param streamSession a new accepted stream session instance
	 * @param[out] handle reference to the custom session handle
	 */
	virtual void* onSessionCreate(StreamSessionView streamSession) = 0;
	/**
	 * @brief Stream session destroy function. (TCP)
	 * @note This function is called synchronously.
	 *
	 * @param streamSession stream session instance
	 * @param reason stream session destruction reason
	 */
	virtual void onSessionDestroy(StreamSessionView streamSession, int reason) = 0;
	/**
	 * @brief Stream session data receive function. (TCP)
	 * @details Server destroys session on this function non zero return result.
	 * @warning This function is called asynchronously from the receive thread!
	 *
	 * @param streamSession stream session instance
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual int onStreamReceive(StreamSessionView streamSession, const uint8_t* receiveBuffer, size_t byteCount) = 0;
	/**
	 * @brief Stream server datagram receive function. (UDP)
	 * @warning This function is called asynchronously from the receive thread!
	 *
	 * @param remoteAddress sender remote socket address
	 * @param[in] receiveBuffer received data buffer
	 * @param byteCount received byte count
	 */
	virtual void onDatagramReceive(SocketAddressView remoteAddress, const uint8_t* receiveBuffer, size_t byteCount) = 0;

	/**
	 * @brief Converts reason value to string.
	 * @param reason target reason value
	 */
	virtual string reasonToString(int reason)
	{
		return reason < NETS_RESULT_COUNT ? netsResultToString(reason) : to_string(reason);
	}

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
	SocketView getSocket() const noexcept { return getStreamServerSocket(instance); }
	/**
	 * @brief Returns true if stream server receive thread is running. (MT-Safe)
	 * @details See the @ref isStreamServerRunning().
	 */
	bool isRunning() const noexcept { return isStreamServerRunning(instance); }
	/**
	 * @brief Returns true if stream server use encrypted connection.
	 * @details See the @ref isStreamServerSecure().
	 */
	bool isSecure() const noexcept { return isStreamServerSecure(instance); }

	/*******************************************************************************************************************
	 * @brief Locks stream server session buffer access. (MT-Safe)
	 * @details See the @ref lockStreamServerSessions().
	 */
	void lockSessions() noexcept { lockStreamServerSessions(instance); }
	/**
	 * @brief Unlocks stream server session buffer access. (MT-Safe)
	 * @details See the @ref unlockStreamServerSessions().
	 */
	void unlockSessions() noexcept { unlockStreamServerSessions(instance); }
	/**
	 * @brief Returns stream server session buffer.
	 * @details See the @ref getStreamServerSessions().
	 * @warning You should lock sessions before getting!
	 */
	StreamSessionView* getSessions() noexcept { return (StreamSessionView*)getStreamServerSessions(instance); }
	/**
	 * @brief Returns stream server session count.
	 * @details See the @ref getStreamServerSessionCount().
	 * @warning You should lock sessions before getting!
	 */
	size_t getSessionCount() noexcept { return getStreamServerSessionCount(instance); }

	/**
	 * @brief Updates specified stream server session.
	 * @details See the @ref updateStreamSession().
	 * @warning You should lock sessions before updating!
	 * @return Zero on success, otherwise failure reason.
	 *
	 * @param streamSession stream session instance to update
	 * @param currentTime current time value
	 */
	int updateSession(StreamSessionView streamSession, double currentTime) noexcept
	{
		return updateStreamSession(instance, streamSession.getInstance(), currentTime);
	}
	/**
	 * @brief Destroys specified stream server session.
	 * @details See the @ref destroyStreamSession().
	 * @warning You should lock sessions before closing!
	 *
	 * @param streamSession stream session instance to close
	 * @param reason stream session destruction reason
	 */
	void destroySession(StreamSessionView streamSession, int reason) noexcept
	{
		destroyStreamSession(instance, streamSession.getInstance(), reason);
	}
	/**
	 * @brief Flushes destroyed stream server sessions.
	 * @details See the @ref flushStreamSessions().
	 * @warning You should lock sessions before closing!
	 */
	void flushSessions() noexcept { flushStreamSessions(instance); }

	/**
	 * @brief Sends datagram to the specified stream session. (UDP)
	 * @details See the @ref streamServerSendDatagram().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param remoteAddress target remote socket IP address
	 * @param[in] data send data buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult sendDatagram(SocketAddressView remoteAddress, const void* data, size_t byteCount) noexcept
	{
		return streamServerSendDatagram(instance, remoteAddress.getInstance(), data, byteCount);
	}
	/**
	 * @brief Sends datagram to the specified session. (UDP)
	 * @details See the @ref streamServerSendDatagram().
	 * @return The operation @ref NetsResult code.

	 * @param remoteAddress target remote socket IP address
	 * @param[in] message datagram message to send
	 */
	NetsResult sendDatagram(SocketAddressView remoteAddress, const OutStreamMessage& message) noexcept
	{
		assert(message.isComplete());
		return streamServerSendDatagram(instance, remoteAddress.getInstance(), message.getBuffer(), message.getSize());
	}
};

inline static void* _onStreamSessionCreate(StreamServer_T* streamServer, StreamSession_T* streamSession)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	return server->onSessionCreate(streamSession);
}
inline static void _onStreamSessionDestroy(StreamServer_T* streamServer, StreamSession_T* streamSession, int reason)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	server->onSessionDestroy(streamSession, reason);
}
inline static int _onStreamSessionReceive(StreamServer_T* streamServer, 
	StreamSession_T* streamSession, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	return server->onStreamReceive(streamSession, receiveBuffer, byteCount);
}
inline static void _onStreamServerDatagram(StreamServer_T* streamServer, 
	SocketAddress_T* remoteAddress, const uint8_t* receiveBuffer, size_t byteCount)
{
	auto server = (IStreamServer*)getStreamServerHandle(streamServer);
	server->onDatagramReceive(remoteAddress, receiveBuffer, byteCount);
}

} // nets