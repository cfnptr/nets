// Copyright 2020-2021 Nikita Fediuchin. All rights reserved.
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

#include "mpnw/datagram_client.h"

struct DatagramClient_T
{
	size_t receiveBufferSize;
	OnDatagramClientReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	Socket socket;
};

MpnwResult createDatagramClient(
	SocketAddress remoteAddress,
	size_t receiveBufferSize,
	OnDatagramClientReceive onReceive,
	void* handle,
	DatagramClient* _datagramClient)
{
	assert(remoteAddress != NULL);
	assert(receiveBufferSize != 0);
	assert(onReceive != NULL);
	assert(_datagramClient != NULL);

	DatagramClient datagramClient = malloc(
		sizeof(DatagramClient_T));

	if (datagramClient == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

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
			ANY_IP_ADDRESS_SERVICE,
			&socketAddress);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_SERVICE,
			&socketAddress);
	}
	else
	{
		abort();
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

	datagramClient->receiveBufferSize = receiveBufferSize;
	datagramClient->onReceive = onReceive;
	datagramClient->handle = handle;
	datagramClient->receiveBuffer = receiveBuffer;
	datagramClient->socket = socket;

	*_datagramClient = datagramClient;
	return SUCCESS_MPNW_RESULT;
}
void destroyDatagramClient(DatagramClient datagramClient)
{
	if (datagramClient == NULL)
		return;
	
	shutdownSocket(
		datagramClient->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(datagramClient->socket);
	free(datagramClient->receiveBuffer);
	free(datagramClient);
}

size_t getDatagramClientReceiveBufferSize(DatagramClient datagramClient)
{
	assert(datagramClient != NULL);
	return datagramClient->receiveBufferSize;
}
OnDatagramClientReceive getDatagramClientOnReceive(DatagramClient datagramClient)
{
	assert(datagramClient != NULL);
	return datagramClient->onReceive;
}
void* getDatagramClientHandle(DatagramClient datagramClient)
{
	assert(datagramClient != NULL);
	return datagramClient->handle;
}
Socket getDatagramClientSocket(DatagramClient datagramClient)
{
	assert(datagramClient != NULL);
	return datagramClient->socket;
}

bool updateDatagramClient(DatagramClient datagramClient)
{
	assert(datagramClient != NULL);

	uint8_t* receiveBuffer =
		datagramClient->receiveBuffer;

	size_t byteCount;

	bool result = socketReceive(
		datagramClient->socket,
		receiveBuffer,
		datagramClient->receiveBufferSize,
		&byteCount);

	if (result == false)
		return false;

	datagramClient->onReceive(
		datagramClient,
		receiveBuffer,
		byteCount);
	return true;
}

bool datagramClientSend(
	DatagramClient datagramClient,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(datagramClient != NULL);
	assert(sendBuffer != NULL);
	assert(byteCount != 0);

	return socketSend(
		datagramClient->socket,
		sendBuffer,
		byteCount);
}
