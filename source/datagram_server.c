#include "mpnw/datagram_server.h"

#include <assert.h>
#include <stdio.h>

struct DatagramServer
{
	size_t bufferSize;
	OnDatagramServerReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	SocketAddress address;
	Socket socket;
};

MpnwResult createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t bufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* _datagramServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(bufferSize != 0);
	assert(onReceive != NULL);
	assert(_datagramServer != NULL);
	assert(isNetworkInitialized() == true);

	DatagramServer datagramServer = malloc(
		sizeof(struct DatagramServer));

	if (datagramServer == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(datagramServer);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service,
			&socketAddress);
	}
	else
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service,
			&socketAddress);
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(datagramServer);
		return mpnwResult;
	}

	Socket socket;

	mpnwResult = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		false,
		NULL,
		&socket);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroySocketAddress(socketAddress);
		free(receiveBuffer);
		free(datagramServer);
		return mpnwResult;
	}

	datagramServer->bufferSize = bufferSize;
	datagramServer->onReceive = onReceive;
	datagramServer->handle = handle;
	datagramServer->receiveBuffer = receiveBuffer;
	datagramServer->address = socketAddress;
	datagramServer->socket = socket;

	*_datagramServer = datagramServer;
	return SUCCESS_MPNW_RESULT;
}

void destroyDatagramServer(DatagramServer server)
{
	assert(isNetworkInitialized() == true);

	if (server == NULL)
		return;

	shutdownSocket(
		server->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(server->socket);
	destroySocketAddress(server->address);
	free(server->receiveBuffer);
	free(server);
}

size_t getDatagramServerBufferSize(DatagramServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->bufferSize;
}

OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->onReceive;
}

void* getDatagramServerHandle(DatagramServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->handle;
}

Socket getDatagramServerSocket(DatagramServer server)
{
	assert(server != NULL);
	assert(isNetworkInitialized() == true);
	return server->socket;
}

bool updateDatagramServer(DatagramServer server)
{
	assert(server != NULL);

	uint8_t* receiveBuffer =
		server->receiveBuffer;

	size_t byteCount;

	bool result = socketReceiveFrom(
		server->socket,
		server->address,
		receiveBuffer,
		server->bufferSize,
		&byteCount);

	if (result == false)
		return false;

	server->onReceive(
		server,
		server->address,
		receiveBuffer,
		byteCount);
	return true;
}

bool datagramServerSend(
	DatagramServer server,
	const void* buffer,
	size_t count,
	SocketAddress address)
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
