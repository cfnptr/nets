#include "mpnw/datagram_server.h"

#include <assert.h>
#include <stdio.h>

struct DatagramServer
{
	size_t bufferSize;
	OnDatagramServerReceive onReceive;
	void* handle;
	uint8_t* buffer;
	SocketAddress* address;
	Socket* socket;
};

DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t bufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	SslContext* sslContext)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(bufferSize != 0);
	assert(onReceive != NULL);
	assert(isNetworkInitialized() == true);

	DatagramServer* server = malloc(sizeof(DatagramServer));

	if (server == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	SocketAddress* address;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service);
	}
	else
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	if (address == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	Socket* socket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		address,
		false,
		false,
		sslContext);

	if (socket == NULL)
	{
		destroySocketAddress(address);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->bufferSize = bufferSize;
	server->onReceive = onReceive;
	server->handle = handle;
	server->buffer = receiveBuffer;
	server->address = address;
	server->socket = socket;
	return server;
}

void destroyDatagramServer(DatagramServer* server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	shutdownSocket(
		server->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(server->socket);
	destroySocketAddress(server->address);
	free(server->buffer);
	free(server);
}

size_t getDatagramServerBufferSize(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->bufferSize;
}

OnDatagramServerReceive getDatagramServerOnReceive(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onReceive;
}

void* getDatagramServerHandle(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->handle;
}

Socket* getDatagramServerSocket(
	const DatagramServer* server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->socket;
}

bool updateDatagramServer(
	DatagramServer* server)
{
	assert(server != NULL);

	uint8_t* buffer = server->buffer;
	size_t byteCount;

	bool result = socketReceiveFrom(
		server->socket,
		buffer,
		server->bufferSize,
		server->address,
		&byteCount);

	if (result == false)
		return false;

	server->onReceive(
		server,
		server->address,
		buffer,
		byteCount);
	return true;
}

bool datagramServerSend(
	DatagramServer* server,
	const void* buffer,
	size_t count,
	const SocketAddress* address)
{
	assert(server != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(address != NULL);
	assert(isNetworkInitialized() == true);

	return socketSendTo(
		server->socket,
		buffer,
		count,
		address);
}
