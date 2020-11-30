#pragma once
#include "mpnw/socket.h"

struct StreamClient;
struct StreamServer;

typedef bool(*StreamClientReceive)(
	struct StreamClient* client,
	size_t count,
	const uint8_t* buffer,
	void* argument);
typedef void(*StreamClientStop)(
	struct StreamClient* client,
	void* argument);

struct StreamClient* createStreamClient(
	enum AddressFamily addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	StreamClientStop stopFunction,
	void* receiveArgument,
	void* stopArgument);
void destroyStreamClient(
	struct StreamClient* client);

bool isStreamClientRunning(
	const struct StreamClient* client);

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

typedef void(*StreamServerAccept)(
	struct StreamServer* server,
	struct StreamClient* client,
	void* argument);
typedef void(*StreamServerStop)(
	struct StreamServer* server,
	void* argument);

struct StreamServer* createStreamServer(
	enum AddressFamily addressFamily,
	const char* portNumber,
	size_t receiveBufferSize,
	StreamServerAccept serverAcceptFunction,
	StreamServerStop serverStopFunction,
	StreamClientReceive clientReceiveFunction,
	StreamClientStop clientStopFunction,
	void* serverAcceptArgument,
	void* serverStopArgument,
	void* clientReceiveArgument,
	void* clientStopArgument);
void destroyStreamServer(
	struct StreamServer* server);

bool isStreamServerRunning(
	const struct StreamServer* server);

