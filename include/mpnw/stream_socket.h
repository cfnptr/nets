#pragma once
#include "mpnw/socket.h"

/* Stream client socket instance handle */
struct StreamClient;
/* Stream server socket instance handle */
struct StreamServer;

/* Stream client socket receive function */
typedef bool(*StreamClientReceive)(
	struct StreamClient* client,
	size_t count,
	const uint8_t* buffer);

/* Stream client receive stop function */
typedef void(*StreamClientStop)(
	struct StreamClient* client);

/*
 * Creates a new stream client socket.
 *
 * bufferSize - message receive buffer size.
 * receiveFunction - message receive function.
 * stopFunction - receive stop function.
 * customData - client function custom data.
 */
struct StreamClient* createStreamClient(
	size_t bufferSize,
	StreamClientReceive receiveFunction,
	StreamClientStop stopFunction,
	void* customData);

/*
 * Destroys stream client socket
 * Shutdowns before destruction.
 *
 * client - pointer to the valid stream client.
*/
void destroyStreamClient(
	struct StreamClient* client);

/*
 * Returns stream client receive buffer size.
 * client - pointer to the valid stream client.
 */
size_t getStreamClientBufferSize(
	const struct StreamClient* client);

/*
 * Returns stream client function custom data.
 * client - pointer to the valid stream client.
 */
void* getStreamClientCustomData(
	const struct StreamClient* client);

/*
 * Returns true if stream client is already started.
 * client - pointer to the valid stream client.
 */
bool isStreamClientStarted(
	const struct StreamClient* client);

/*
 * Returns true if stream client is still running.
 * client - pointer to the valid stream client.
 */
bool isStreamClientRunning(
	const struct StreamClient* client);

/*
 * Starts a new stream client receive thread.
 * Binds socket address before thread start.
 * Returns true if stream client has been started.
 *
 * client - pointer to the valid stream client.
 * family - socket internet protocol address family.
 */
bool startStreamClient(
	struct StreamClient* client,
	enum AddressFamily family);

/*
 * Returns a new local address on success, otherwise null.
 * client - pointer to the valid stream client.
 */
struct SocketAddress* getStreamClientLocalAddress(
	const struct StreamClient* client);

/*
 * Returns a new remote address on success, otherwise null.
 * client - pointer to the valid stream client.
 */
struct SocketAddress* getStreamClientRemoteAddress(
	const struct StreamClient* client);

/*
 * Returns stream client message receive timeout time.
 * client - pointer to the valid stream client.
 */
size_t getStreamClientReceiveTimeout(
	const struct StreamClient* client);

/*
 * Sets stream client message receive timeout time.
 * client - pointer to the valid stream client.
 */
void setStreamClientReceiveTimeout(
	struct StreamClient* client,
	size_t milliseconds);

/*
 * Returns stream client message send timeout time.
 * client - pointer to the valid stream client.
 */
size_t getStreamClientSendTimeout(
	const struct StreamClient* client);

/*
 * Sets stream client message send timeout time.
 * client - pointer to the valid stream client.
 */
void setStreamClientSendTimeout(
	struct StreamClient* client,
	size_t milliseconds);

/*
 * Returns true on successful stream client message send.
 * Stream client should be started before function call.
 *
 * client - pointer to the valid stream client.
 * buffer - pointer to the valid send buffer.
 * count - message byte count to send.
 */
bool streamClientSend(
	struct StreamClient* client,
	void* buffer,
	size_t count);

/* Stream server socket accept function */
typedef bool(*StreamServerAccept)(
	struct StreamServer* server,
	struct StreamClient* client);

/* Stream server accept stop function */
typedef void(*StreamServerStop)(
	struct StreamServer* server);

/*
 * Creates a new stream server socket.
 *
 * clientBufferSize - client message receive buffer size.
 * serverAcceptFunction - server socket accept function.
 * serverStopFunction - server accept stop function.
 * clientReceiveFunction - client message receive function.
 * clientStopFunction - client receive stop function.
 * customData - server and client function custom data.
 */
struct StreamServer* createStreamServer(
	size_t clientBufferSize,
	StreamServerAccept serverAcceptFunction,
	StreamServerStop serverStopFunction,
	StreamClientReceive clientReceiveFunction,
	StreamClientStop clientStopFunction,
	void* customData);

/*
 * Destroys stream server socket
 * Shutdowns before destruction.
 *
 * server - pointer to the valid stream server.
*/
void destroyStreamServer(
	struct StreamServer* server);

/*
 * Returns stream server client receive buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerClientBufferSize(
	const struct StreamServer* server);

/*
 * Returns stream server custom data.
 * server - pointer to the valid stream server.
 */
void* getStreamServerCustomData(
	const struct StreamServer* server);

/*
 * Returns true if stream server is already started.
 * server - pointer to the valid stream server.
 */
bool isStreamServerStarted(
	const struct StreamServer* server);

/*
 * Returns true if stream server is still running.
 * server - pointer to the valid stream server.
 */
bool isStreamServerRunning(
	const struct StreamServer* server);

/*
 * Starts a new stream server accept thread.
 * Binds socket address before thread start.
 * Returns true if stream server has been started.
 *
 * server - pointer to the valid stream server.
 * family - socket internet protocol address family.
 * service - local socket address service name.
 */
bool startStreamServer(
	struct StreamServer* server,
	enum AddressFamily family,
	const char* service);

/*
 * Returns a new local address on success, otherwise null.
 * server - pointer to the valid stream server.
 */
struct SocketAddress* getStreamServerLocalAddress(
	const struct StreamServer* server);
