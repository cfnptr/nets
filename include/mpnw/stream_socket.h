#pragma once
#include "mpnw/socket.h"

struct StreamClient;
struct StreamServer;

typedef bool(*StreamClientReceive)(
	struct StreamClient* client,
	size_t count,
	const uint8_t* buffer);
typedef void(*StreamClientStop)(
	struct StreamClient* client);

struct StreamClient* createStreamClient(
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	StreamClientStop stopFunction,
	void* customData);
void destroyStreamClient(
	struct StreamClient* client);

size_t getStreamClientReceiveBufferSize(
	const struct StreamClient* client);
void* getStreamClientCustomData(
	const struct StreamClient* client);

bool isStreamClientStarted(
	const struct StreamClient* client);
bool isStreamClientRunning(
	const struct StreamClient* client);

void startStreamClient(
	struct StreamClient* client,
	enum AddressFamily addressFamily);

struct SocketAddress* getStreamClientLocalAddress(
	const struct StreamClient* client);
struct SocketAddress* getStreamClientRemoteAddress(
	const struct StreamClient* client);

size_t getStreamClientReceiveTimeout(
	const struct StreamClient* client);
void setStreamClientReceiveTimeout(
	struct StreamClient* client,
	size_t milliseconds);

size_t getStreamClientSendTimeout(
	const struct StreamClient* client);
void setStreamClientSendTimeout(
	struct StreamClient* client,
	size_t milliseconds);

bool streamClientSend(
	struct StreamClient* client,
	void* buffer,
	size_t count);

typedef bool(*StreamServerAccept)(
	struct StreamServer* server,
	struct StreamClient* client);
typedef void(*StreamServerStop)(
	struct StreamServer* server);

struct StreamServer* createStreamServer(
	size_t receiveBufferSize,
	StreamServerAccept serverAcceptFunction,
	StreamServerStop serverStopFunction,
	StreamClientReceive clientReceiveFunction,
	StreamClientStop clientStopFunction,
	void* customData);
void destroyStreamServer(
	struct StreamServer* server);

size_t getStreamServerReceiveBufferSize(
	const struct StreamServer* server);
void* getStreamServerCustomData(
	const struct StreamServer* server);

bool isStreamServerStarted(
	const struct StreamServer* server);
bool isStreamServerRunning(
	const struct StreamServer* server);

void startStreamServer(
	struct StreamServer* server,
	enum AddressFamily addressFamily,
	const char* portNumber);

struct SocketAddress* getStreamServerLocalAddress(
	const struct StreamServer* server);
