#include "mpnw/datagram_client.h"
#include <assert.h>

struct DatagramClient
{
	size_t bufferSize;
	OnDatagramClientReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	Socket socket;
};

MpnwResult createDatagramClient(
	SocketAddress remoteAddress,
	size_t bufferSize,
	OnDatagramClientReceive onReceive,
	void* handle,
	DatagramClient* _datagramClient)
{
	assert(remoteAddress != NULL);
	assert(bufferSize != 0);
	assert(onReceive != NULL);
	assert(_datagramClient != NULL);
	assert(isNetworkInitialized() == true);

	DatagramClient datagramClient = malloc(
		sizeof(struct DatagramClient));

	if (datagramClient == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(datagramClient);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	uint8_t addressFamily =
		getSocketAddressFamily(remoteAddress);

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_PORT,
			&socketAddress);
	}
	else
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_PORT,
			&socketAddress);
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(datagramClient);
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

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(datagramClient);
		return mpnwResult;
	}

	bool result = connectSocket(
		socket,
		remoteAddress);

	if (result == false)
	{
		destroySocket(socket);
		free(receiveBuffer);
		free(datagramClient);
		return FAILED_TO_CONNECT_SOCKET_MPNW_RESULT;
	}

	datagramClient->bufferSize = bufferSize;
	datagramClient->onReceive = onReceive;
	datagramClient->handle = handle;
	datagramClient->receiveBuffer = receiveBuffer;
	datagramClient->socket = socket;

	*_datagramClient = datagramClient;
	return SUCCESS_MPNW_RESULT;
}

void destroyDatagramClient(DatagramClient client)
{
	assert(isNetworkInitialized() == true);

	if (client == NULL)
		return;

	shutdownSocket(
		client->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(client->socket);
	free(client->receiveBuffer);
	free(client);
}

size_t getDatagramClientBufferSize(DatagramClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->bufferSize;
}

OnDatagramClientReceive getDatagramClientOnReceive(DatagramClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->onReceive;
}

void* getDatagramClientHandle(DatagramClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->handle;
}

Socket getDatagramClientSocket(DatagramClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->socket;
}

bool updateDatagramClient(DatagramClient client)
{
	assert(client != NULL);

	uint8_t* receiveBuffer =
		client->receiveBuffer;

	size_t byteCount;

	bool result = socketReceive(
		client->socket,
		receiveBuffer,
		client->bufferSize,
		&byteCount);

	if (result == false)
		return false;

	client->onReceive(
		client,
		receiveBuffer,
		byteCount);
	return true;
}

bool datagramClientSend(
	DatagramClient client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(isNetworkInitialized() == true);

	return socketSend(
		client->socket,
		buffer,
		count);
}
