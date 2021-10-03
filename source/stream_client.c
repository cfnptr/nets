#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <assert.h>

struct StreamClient
{
	size_t bufferSize;
	OnStreamClientReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	Socket socket;
};

MpnwResult createStreamClient(
	AddressFamily addressFamily,
	size_t bufferSize,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* _streamClient)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(bufferSize != 0);
	assert(onReceive != NULL);
	assert(_streamClient != NULL);
	assert(isNetworkInitialized() == true);

	StreamClient streamClient = malloc(
		sizeof(struct StreamClient));

	if (streamClient == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		bufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(streamClient);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

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
		free(streamClient);
		return mpnwResult;
	}

	Socket socket;

	mpnwResult = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		false,
		sslContext,
		&socket);

	destroySocketAddress(socketAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(receiveBuffer);
		free(streamClient);
		return mpnwResult;
	}

	streamClient->bufferSize = bufferSize;
	streamClient->onReceive = onReceive;
	streamClient->handle = handle;
	streamClient->receiveBuffer = receiveBuffer;
	streamClient->socket = socket;

	*_streamClient = streamClient;
	return SUCCESS_MPNW_RESULT;
}

void destroyStreamClient(StreamClient client)
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

size_t getStreamClientBufferSize(StreamClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->bufferSize;
}

OnStreamClientReceive getStreamClientOnReceive(StreamClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->onReceive;
}

void* getStreamClientHandle(StreamClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->handle;
}

Socket getStreamClientSocket(StreamClient client)
{
	assert(client != NULL);
	assert(isNetworkInitialized() == true);
	return client->socket;
}

bool connectStreamClient(
	StreamClient client,
	SocketAddress address,
	double timeoutTime)
{
	assert(client != NULL);
	assert(address != NULL);
	assert(timeoutTime >= 0.0);
	assert(isNetworkInitialized() == true);

	Socket socket = client->socket;
	double timeout = getCurrentClock() + timeoutTime;

	while (getCurrentClock() < timeout)
	{
		bool result = connectSocket(
			socket,
			address);

		if (result == true)
			goto CONNECT_SSL;

		sleepThread(0.001);
	}

	return false;

CONNECT_SSL:

	if (getSocketSslContext(socket) == NULL)
		return true;

	while (getCurrentClock() < timeout)
	{
		bool result = connectSslSocket(socket);

		if (result == true)
			return true;

		sleepThread(0.001);
	}

	return false;
}

bool updateStreamClient(StreamClient client)
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

bool streamClientSend(
	StreamClient client,
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
