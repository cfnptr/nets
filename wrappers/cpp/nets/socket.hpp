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
 * @brief Network socket functions.
 * @details See the @ref socket.h
 */

#pragma once
#include "nets/error.hpp"
#include <utility>
#include <cstring>

extern "C"
{
#include "nets/socket.h"
}

namespace nets
{

/**
 * @brief Socket IP address instance view.
 * @details See the @ref socket.h
 */
struct SocketAddressView
{
protected:
	SocketAddress_T* instance = nullptr;
public:
	/**
	 * @brief Creates a new socket IP address view.
	 * @param[in] instance target socket instance
	 */
	SocketAddressView(SocketAddress_T* instance) noexcept : instance(instance) { }
	/**
	 * @brief Destroys socket IP address instance.
	 * @details See the @ref destroySocketAddress().
	 */
	void destroy() noexcept
	{
		destroySocketAddress(instance);
		instance = nullptr;
	}

	/*******************************************************************************************************************
	 * @brief Returns socket IP address view instance.
	 */
	SocketAddress_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns socket IP address family type.
	 * @details See the @ref getSocketAddressFamily().
	 */
	SocketFamily getFamily() const noexcept { return getSocketAddressFamily(instance); }
	/**
	 * @brief Returns socket IP address byte array size.
	 * @details See the @ref getSocketAddressIpSize().
	 */
	size_t getIpSize() const noexcept { return getSocketAddressIpSize(instance); }
	/**
	 * @brief Returns true if socket IP address is any address.
	 * @details See the @ref isSocketAddressAny().
	 */
	bool isAny() const noexcept { return isSocketAddressAny(instance); }
	/**
	 * @brief Returns true if socket IP address is loopback address.
	 * @details See the @ref isSocketAddressLoopback().
	 */
	bool isLoopback() const noexcept { return isSocketAddressLoopback(instance); }
	/**
	 * @brief Returns true if socket IP address is IPv4 mapped IPv6.
	 * @details See the @ref isSocketAddressMappedV4().
	 */
	bool isMappedV4() const noexcept { return isSocketAddressMappedV4(instance); }

	/**
	 * @brief Returns socket IP address byte array.
	 * @details See the @ref getSocketAddressIP().
	 */
	const uint8_t* getIP() const noexcept { return getSocketAddressIP(instance); }
	/**
	 * @brief Sets socket IP address byte array.
	 * @details See the @ref setSocketAddressIP().
	 * @param[in] ip target IP address byte array
	 */
	void setIP(const uint8_t* ip) noexcept { setSocketAddressIP(instance, ip); }

	/**
	 * @brief Returns socket IP address port number.
	 * @details See the @ref getSocketAddressPort().
	 */
	uint16_t getPort() const noexcept { return getSocketAddressPort(instance); }
	/**
	 * @brief Sets socket IP address port number.
	 * @details See the @ref setSocketAddressPort().
	 * @param port target IP address port number
	 */
	void setPort(uint16_t port) noexcept { setSocketAddressPort(instance, port); }

	/*******************************************************************************************************************
	 * @brief Returns socket IP address numeric host name.
	 * @details See the @ref getSocketAddressHost().
	 * @return True on success, otherwise false.
	 *
	 * @param[out] host pointer to the host name string
	 * @param length host name string length (including null terminator)
	 */
	void getHost(char* host, size_t length) const noexcept { getSocketAddressHost(instance, host, length); }
	/**
	 * @brief Returns socket IP address numeric host name.
	 * @details See the @ref getSocketAddressHost().
	 * @return True on success, otherwise false.
	 * @param[out] host target host name string
	 */
	void getHost(std::string& host) const
	{
		host.resize(MAX_NUMERIC_HOST_LENGTH);
		getSocketAddressHost(instance, host.data(), MAX_NUMERIC_HOST_LENGTH);
		host.resize(strlen(host.c_str()));
	}

	/**
	 * @brief Returns socket IP address numeric service name.
	 * @details See the @ref getSocketAddressService().
	 * @return True on success, otherwise false.
	 *
	 * @param[out] service pointer to the service name string
	 * @param length service name string length (including null terminator)
	 */
	void getService(char* service, size_t length) const noexcept { getSocketAddressService(instance, service, length); }
	/**
	 * @brief Returns socket IP address numeric service name.
	 * @details See the @ref getSocketAddressService().
	 * @return True on success, otherwise false.
	 * @param[out] service target service name string
	 */
	void getService(std::string& service) const
	{
		service.resize(MAX_NUMERIC_SERVICE_LENGTH);
		getSocketAddressService(instance, service.data(), MAX_NUMERIC_SERVICE_LENGTH);
		service.resize(strlen(service.c_str()));
	}

	/**
	 * @brief Returns socket IP address numeric host and service name.
	 * @details See the @ref getSocketAddressHostService().
	 * @return True on success, otherwise false.
	 *
	 * @param[out] host pointer to the host name string
	 * @param hostLength host name string length (including null terminator)
	 * @param[out] service pointer to the service name string
	 * @param serviceLength service name string length (including null terminator)
	 */
	void getHostService(char* host, size_t hostLength, char* service, size_t serviceLength) const noexcept
	{
		getSocketAddressHostService(instance, host, hostLength, service, serviceLength);
	}
	/**
	 * @brief Returns socket IP address numeric host and service name.
	 * @details See the @ref getSocketAddressHostService().
	 * @return True on success, otherwise false.
	 *
	 * @param[out] host target host name string
	 * @param[out] service target service name string
	 */
	void getHostService(std::string& host, std::string& service) const
	{
		host.resize(MAX_NUMERIC_HOST_LENGTH); service.resize(MAX_NUMERIC_SERVICE_LENGTH);
		getSocketAddressHostService(instance, host.data(), MAX_NUMERIC_HOST_LENGTH, 
			service.data(), MAX_NUMERIC_SERVICE_LENGTH);
		host.resize(strlen(host.c_str())); service.resize(strlen(service.c_str()));
	}

	/*******************************************************************************************************************
	 * @brief Resolves a new socket IP address array. (Blocking call)
	 * @details See the @ref resolveSocketAddresses().
	 * @warning This may be a slow running operation!
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] host socket IP address host name string
	 * @param[in] service socket IP address service name string (port)
	 * @param family socket IP address family type
	 * @param type socket communication protocol type
	 * @param[out] socketAddresses reference to the socket address array
	 * @param[out] addressCount reference to the socket address count
	 */
	static NetsResult resolve(const char* host, const char* service, SocketFamily family,
		SocketType type, SocketAddressView*& socketAddresses, size_t& addressCount) noexcept
	{
		return resolveSocketAddresses(host, service, family,
			type, (SocketAddress_T***)&socketAddresses, &addressCount);
	}
	/**
	 * @brief Destroys resolved socket IP address array.
	 * @details See the @ref destroySocketAddresses().
	 *
	 * @param[in] socketAddresses socket IP address array
	 * @param addressCount socket address count
	 */
	static void destroy(SocketAddressView* socketAddresses, size_t addressCount) noexcept
	{
		destroySocketAddresses((SocketAddress_T**)socketAddresses, addressCount);
	}

	/**
	 * @brief Copies source socket IP address to the destination.
	 * @details See the @ref copySocketAddress().
	 *
	 * @param sourceAddress source socket address instance
	 * @param destinationAddress destination socket address instance
	 */
	static void copy(SocketAddressView sourceAddress, SocketAddressView destinationAddress) noexcept
	{
		copySocketAddress(sourceAddress.instance, destinationAddress.instance);
	}
	/**
	 * @brief Compares two socket IP addresses.
	 * @details See the @ref compareSocketAddress().
	 *
	 * @param[in] a first socket address instance
	 * @param[in] b second socket address instance
	 */
	static int compare(SocketAddressView a, SocketAddressView b) noexcept
	{
		return compareSocketAddress(a.instance, b.instance);
	}
};

/***********************************************************************************************************************
 * @brief Socket IP address instance handle.
 * @details See the @ref socket.h
 */
struct SocketAddress final : public SocketAddressView
{
	SocketAddress(const SocketAddress&) = delete;
	SocketAddress(SocketAddress&& r) noexcept : SocketAddressView(nullptr)
	{
		instance = std::exchange(r.instance, nullptr);
	}
	SocketAddress& operator=(SocketAddress&) = delete;
	SocketAddress& operator=(SocketAddress&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new any socket IP address instance.
	 * @details See the @ref createAnySocketAddress().
	 * @param family socket IP address family type
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	SocketAddress(SocketFamily family = IP_V6_SOCKET_FAMILY) : SocketAddressView(nullptr)
	{
		auto result = createAnySocketAddress(family, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Creates a new socket IP address instance.
	 * @details See the @ref createSocketAddress().
	 *
	 * @param[in] host socket IP address host name string
	 * @param[in] service socket IP address service name string (port)
	 * 
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	SocketAddress(const char* host, const char* service) : SocketAddressView(nullptr)
	{
		auto result = createSocketAddress(host, service, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}

	/**
	 * @brief Destroys socket IP address instance.
	 * @details See the @ref destroySocketAddress().
	 */
	~SocketAddress() { destroySocketAddress(instance); }

	/**
	 * @brief Create a new socket IP address copy instance.
	 * @details See the @ref createSocketAddressCopy().
	 */
	SocketAddress createCopy() const noexcept
	{
		SocketAddress socketAddress;
		socketAddress.instance = createSocketAddressCopy(instance);
		if (!socketAddress.instance) abort();
		return socketAddress;
	}
};

/***********************************************************************************************************************
 * @brief Secure socket layer (SSL) context instance view.
 * @details See the @ref socket.h
 */
struct SslContextView
{
protected:
	SslContext_T* instance = nullptr;
public:
	/**
	 * @brief Creates a new socket SSL context view.
	 * @param[in] instance target socket instance
	 */
	SslContextView(SslContext_T* instance) noexcept : instance(instance) { }
	/**
	 * @brief Destroys socket SSL context instance.
	 * @details See the @ref destroySslContext().
	 */
	void destroy() noexcept
	{
		destroySslContext(instance);
		instance = nullptr;
	}

	/**
	 * @brief Returns socket SSL context view instance.
	 */
	SslContext_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns socket SSL context security protocol type.
	 * @details See the @ref getSslContextProtocol().
	 */
	SslProtocol getProtocol() const noexcept { return getSslContextProtocol(instance); }
};

/***********************************************************************************************************************
 * @brief Secure socket layer (SSL) context instance handle.
 * @details See the @ref socket.h
 */
struct SslContext final : public SslContextView
{
	SslContext(const SslContext&) = delete;
	SslContext(SslContext&& r) noexcept : SslContextView(nullptr)
	{
		instance = std::exchange(r.instance, nullptr);
	}
	SslContext& operator=(SslContext&) = delete;
	SslContext& operator=(SslContext&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Create a new public socket SSL context.
	 * @details See the @ref createPublicSslContext().
	 *
	 * @param sslProtocol socket SSL security protocol type
	 * @param[in] certificateFilePath certificate file path string or nullptr
	 * @param[in] certificatesDirectory certificates directory path string or nullptr
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	SslContext(SslProtocol sslProtocol = TLS_SECURITY_PROTOCOL, const char* certificateFilePath = nullptr, 
		const char* certificatesDirectory = nullptr) : SslContextView(nullptr)
	{
		auto result = createPublicSslContext(sslProtocol, certificateFilePath, certificatesDirectory, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Create a new private socket SSL context.
	 * @details See the @ref createPrivateSslContext().
	 *
	 * @param sslProtocol socket SSL security protocol type
	 * @param[in] certificateFilePath certificates file path string
	 * @param[in] privateKeyFilePath private key file path string
	 * @param certificateChain file path is certificate chain
	 *
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	SslContext(SslProtocol sslProtocol, const char* certificateFilePath, 
		const char* privateKeyFilePath, bool certificateChain = false) : SslContextView(nullptr)
	{
		auto result = createPrivateSslContext(sslProtocol, certificateFilePath, 
			privateKeyFilePath, certificateChain, &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}

	/**
	 * @brief Destroys socket SSL context instance.
	 * @details See the @ref destroySslContext().
	 */
	~SslContext() { destroySslContext(instance); }
};

/***********************************************************************************************************************
 * @brief Network socket instance view.
 * @details See the @ref socket.h
 */
struct SocketView
{
protected:
	Socket_T* instance = nullptr;
public:
	/**
	 * @brief Creates a new network socket view.
	 * @param[in] instance target socket instance
	 */
	SocketView(Socket_T* instance) noexcept : instance(instance) { }
	/**
	 * @brief Destroys network socket instance.
	 * @details See the @ref destroySocket().
	 */
	void destroy() noexcept
	{
		destroySocket(instance);
		instance = nullptr;
	}

	/*******************************************************************************************************************
	 * @brief Returns socket SSL context view instance.
	 */
	Socket_T* getInstance() const noexcept { return instance; }
	/**
	 * @brief Returns socket communication protocol type.
	 * @details See the @ref getSocketType().
	 */
	SocketType getType() const noexcept { return getSocketType(instance); }
	/**
	 * @brief Returns socket internet protocol (IP) address family type.
	 * @details See the @ref getSocketFamily().
	 */
	SocketFamily getFamily() const noexcept { return getSocketFamily(instance); }
	/**
	 * @brief Returns true if socket is in blocking mode.
	 * @details See the @ref isSocketBlocking().
	 */
	bool isBlocking() const noexcept { return isSocketBlocking(instance); }
	/**
	 * @brief Returns true if IPv6 socket is not accepting IPv4 connections.
	 * @details See the @ref isSocketOnlyIPv6().
	 */
	bool isOnlyIPv6() const noexcept { return isSocketOnlyIPv6(instance); }

	/**
	 * @brief Gets local socket IP address.
	 * @details See the @ref getSocketLocalAddress().
	 * @throw Error with a result string on failure.
	 * @param[out] socketAddress socket IP address instance
	 */
	void getLocalAddress(SocketAddressView socketAddress) const
	{
		if (!getSocketLocalAddress(instance, socketAddress.getInstance()))
			throw Error("Failed to get socket local address");
	}
	/**
	 * @brief Gets remote socket IP address.
	 * @details See the @ref getSocketRemoteAddress().
	 * @throw Error with a result string on failure.
	 * @param[out] socketAddress socket IP address instance
	 */
	void getRemoteAddress(SocketAddressView socketAddress) const
	{
		if (!getSocketRemoteAddress(instance, socketAddress.getInstance()))
			throw Error("Failed to get socket remote address");
	}

	/*******************************************************************************************************************
	 * @brief Returns socket SSL context instance.
	 * @details See the @ref getSocketSslContext().
	 */
	SslContextView getSslContext() const noexcept { return getSocketSslContext(instance); }
	/**
	 * @brief Returns socket internal handle.
	 * @details See the @ref getSocketHandle().
	 */
	void* getHandle() const noexcept { return getSocketHandle(instance); }

	/**
	 * @brief Returns true if stream socket sends without caching.
	 * @details See the @ref isSocketNoDelay().
	 */
	bool isNoDelay() const noexcept { return isSocketNoDelay(instance); }
	/**
	 * @brief Sets socket no delay mode.
	 * @details Does stream socket sends without caching.
	 * @param value no delay mode value
	 */
	void setNoDelay(bool value) noexcept { setSocketNoDelay(instance, value); }

	/**
	 * @brief Returns true if socket is in the listening state.
	 * @details See the @ref isSocketListening().
	 */
	bool isListening() const noexcept { return isSocketListening(instance); }
	/**
	 * @brief Returns socket pending connections queue size.
	 * @details See the @ref getSocketQueueSize().
	 */
	size_t getQueueSize() const noexcept { return getSocketQueueSize(instance); }

	/*******************************************************************************************************************
	 * @brief Puts socket in a listening state.
	 * @details See the @ref listenSocket().
	 * @return The operation @ref NetsResult code.
	 * @param queueSize pending connections queue size
	 */
	NetsResult listen(size_t queueSize = 256) noexcept { return listenSocket(instance, queueSize); }

	/**
	 * @brief Accepts a new socket connection.
	 * @note You should destroy accepted socket instance manually!
	 * @details See the @ref acceptSocket().
	 * @return The operation @ref NetsResult code.
	 * @param[out] accepted reference to the accepted socket
	 */
	NetsResult accept(SocketView& accepted) noexcept
	{
		Socket_T* acceptedSocket;
		auto result = acceptSocket(instance, &acceptedSocket);
		if (result == SUCCESS_NETS_RESULT)
			accepted = acceptedSocket;
		return result;
	}
	/**
	 * @brief Accepts socket SSL connection.
	 * @details See the @ref acceptSslSocket().
	 * @return The operation @ref NetsResult code.
	 */
	NetsResult acceptSsl() noexcept { return acceptSslSocket(instance); }

	/**
	 * @brief Connects socket to the specified remote address.
	 * @details See the @ref connectSocket().
	 * @return The operation @ref NetsResult code.
	 * @param remoteAddress remote socket IP address instance
	 */
	NetsResult connect(SocketAddressView remoteAddress) noexcept
	{
		return connectSocket(instance, remoteAddress.getInstance());
	}
	/**
	 * @brief Establishes socket SSL connection.
	 * @details See the @ref connectSslSocket().
	 * @return The operation @ref NetsResult code.
	 * @param[in] hostname remote socket SNI hostname or NULL
	 */
	NetsResult connectSsl(const char* hostname = nullptr) noexcept
	{
		return connectSslSocket(instance, hostname);
	}

	/**
	 * @brief Shutdowns part of the full-duplex connection.
	 * @details See the @ref shutdownSocket().
	 * @return The operation @ref NetsResult code.
	 * @param shutdown socket connection shutdown mode
	 */
	NetsResult shutdown(SocketShutdown shutdown = RECEIVE_SEND_SOCKET_SHUTDOWN) noexcept
	{
		return shutdownSocket(instance, shutdown);
	}

	/*******************************************************************************************************************
	 * @brief Receives pending socket data.
	 * @details See the @ref socketReceive().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[out] receiveBuffer data receive buffer
	 * @param bufferSize data receive buffer size in bytes
	 * @param[out] byteCount reference to the received byte count
	 */
	NetsResult receive(void* receiveBuffer, size_t bufferSize, size_t& byteCount) noexcept
	{
		return socketReceive(instance, receiveBuffer, bufferSize, &byteCount);
	}
	/**
	 * @brief Sends specified data to the remote socket.
	 * @details See the @ref socketSend().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] sendBuffer data send buffer
	 * @param byteCount data byte count to send
	 */
	NetsResult send(const void* sendBuffer, size_t byteCount)
	{
		return socketSend(instance, sendBuffer, byteCount);
	}
	/**
	 * @brief Sends specified data to the remote socket.
	 * @details See the @ref socketSend().
	 * @return The operation @ref NetsResult code.
	 *
	 * @tparam T type of the send data
	 * @param[in] data target data to send
	 */
	template<class T>
	NetsResult send(const T& data) { return socketSend(instance, &data, sizeof(T)); }

	/*******************************************************************************************************************
	 * @brief Receives pending data from the remote socket.
	 * @details See the @ref socketReceiveFrom().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[out] remoteAddress remote socket IP address
	 * @param[out] receiveBuffer data receive buffer
	 * @param bufferSize data receive buffer size in bytes
	 * @param[out] byteCount reference to the received byte count
	 */
	NetsResult receiveFrom(SocketAddressView remoteAddress, 
		void* receiveBuffer, size_t bufferSize, size_t& byteCount) noexcept
	{
		return socketReceiveFrom(instance, remoteAddress.getInstance(), receiveBuffer, bufferSize, &byteCount);
	}
	/**
	 * @brief Sends specified data to the remote socket.
	 * @details See the @ref socketSendTo().
	 * @return The operation @ref NetsResult code.
	 *
	 * @param[in] sendBuffer data send buffer
	 * @param byteCount data byte count to send
	 * @param remoteAddress destination remote socket IP address
	 */
	NetsResult sendTo(const void* sendBuffer, size_t byteCount, SocketAddressView remoteAddress) noexcept
	{
		return socketSendTo(instance, sendBuffer, byteCount, remoteAddress.getInstance());
	}
	/**
	 * @brief Sends specified data to the remote socket.
	 * @details See the @ref socketSendTo().
	 * @return The operation @ref NetsResult code.
	 *
	 * @tparam T type of the send data
	 * @param[in] data target data to send
	 * @param remoteAddress destination remote socket IP address
	 */
	template<class T>
	NetsResult sendTo(const T& data, SocketAddressView remoteAddress) noexcept
	{
		return socketSendTo(instance, &data, sizeof(T), remoteAddress.getInstance());
	}

	/**
	 * @brief Disablea SIGPIPE signals on Linux for a current thread. 
	 */
	static void disableSigpipe() noexcept { ::disableSigpipe(); }
};

/***********************************************************************************************************************
 * @brief Network socket instance handle.
 * @details See the @ref socket.h
 */
struct Socket final : public SocketView
{
	Socket(const Socket&) = delete;
	Socket(Socket&& r) noexcept : SocketView(nullptr)
	{
		instance = std::exchange(r.instance, nullptr);
	}
	Socket& operator=(Socket&) = delete;
	Socket& operator=(Socket&& r) noexcept
	{
		instance = std::exchange(r.instance, nullptr);
		return *this;
	}

	/**
	 * @brief Creates a new network socket instance.
	 * @details See the @ref createSocket().
	 *
	 * @param type socket communication protocol type
	 * @param family internet protocol address family
	 * @param localAddress socket local bind address instance
	 * @param isBlocking create socket in blocking mode
	 * @param isOnlyIPv6 create socket in IPv6 only mode
	 * @param sslContext socket SSL context instance or nullptr
	 * 
	 * @throw Error with a @ref NetsResult string on failure.
	 */
	Socket(SocketType type, SocketFamily family, SocketAddressView localAddress, bool isBlocking = true, 
		bool isOnlyIPv6 = false, SslContextView sslContext = nullptr) : SocketView(nullptr)
	{
		auto result = createSocket(type, family, localAddress.getInstance(), 
			isBlocking, isOnlyIPv6, sslContext.getInstance(), &instance);
		if (result != SUCCESS_NETS_RESULT)
			throw Error(netsResultToString(result));
	}
	/**
	 * @brief Destroys network socket instance.
	 * @details See the @ref destroySocket().
	 */
	~Socket() { destroySocket(instance); }
};

} // nets