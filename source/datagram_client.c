#include "mpnw/datagram_client.h"
#include <assert.h>

struct DatagramClient
{
	size_t bufferSize;
	OnDatagramClientReceive onReceive;
	void* handle;
	uint8_t* buffer;
	Socket socket;
};

DatagramClient createDatagramClient(
	SocketAddress remoteAddress,
	size_t bufferSize,
	OnDatagramClientReceive onReceive,
	void* handle)
{
	assert(remoteAddress != NULL);
	assert(bufferSize != 0);
	assert(onReceive != NULL);
	assert(isNetworkInitialized() == true);

	DatagramClient client = malloc(
		sizeof(struct DatagramClient));

	if (client == NULL)
		return NULL;

	uint8_t* buffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (buffer == NULL)
	{
		free(client);
		return NULL;
	}

	uint8_t addressFamily = getSocketAddressFamily(
		remoteAddress);

	SocketAddress address;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_PORT);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		address = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_PORT);
	}
	else
	{
		free(buffer);
		free(client);
		return NULL;
	}

	if (address == NULL)
	{
		free(buffer);
		free(client);
		return NULL;
	}

	Socket socket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		address,
		false,
		false,
		NULL);

	destroySocketAddress(address);

	if (socket == NULL)
	{
		free(buffer);
		free(client);
		return NULL;
	}

	bool result = connectSocket(
		socket,
		remoteAddress);

	if (result == false)
	{
		destroySocket(socket);
		free(buffer);
		free(client);
		return NULL;
	}

	client->bufferSize = bufferSize;
	client->onReceive = onReceive;
	client->handle = handle;
	client->buffer = buffer;
	client->socket = socket;
	return client;
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
	free(client->buffer);
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

	uint8_t* buffer = client->buffer;
	size_t byteCount;

	bool result = socketReceive(
		client->socket,
		buffer,
		client->bufferSize,
		&byteCount);

	if (result == false)
		return false;

	client->onReceive(
		client,
		buffer,
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
