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

#include "mpnw/datagram_server.h"

#include <assert.h>
#include <stdio.h>

struct DatagramServer
{
	size_t receiveBufferSize;
	OnDatagramServerReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	SocketAddress address;
	Socket socket;
};

MpnwResult createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t receiveBufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* _datagramServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(receiveBufferSize != 0);
	assert(onReceive != NULL);
	assert(_datagramServer != NULL);
	assert(isNetworkInitialized() == true);

	DatagramServer datagramServer = malloc(
		sizeof(struct DatagramServer));

	if (datagramServer == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

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

	datagramServer->receiveBufferSize = receiveBufferSize;
	datagramServer->onReceive = onReceive;
	datagramServer->handle = handle;
	datagramServer->receiveBuffer = receiveBuffer;
	datagramServer->address = socketAddress;
	datagramServer->socket = socket;

	*_datagramServer = datagramServer;
	return SUCCESS_MPNW_RESULT;
}

void destroyDatagramServer(DatagramServer datagramServer)
{
	assert(isNetworkInitialized() == true);

	if (datagramServer == NULL)
		return;

	shutdownSocket(
		datagramServer->socket,
		RECEIVE_SEND_SOCKET_SHUTDOWN);
	destroySocket(datagramServer->socket);
	destroySocketAddress(datagramServer->address);
	free(datagramServer->receiveBuffer);
	free(datagramServer);
}

size_t getDatagramServerReceiveBufferSize(DatagramServer datagramServer)
{
	assert(datagramServer != NULL);
	assert(isNetworkInitialized() == true);
	return datagramServer->receiveBufferSize;
}

OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer datagramServer)
{
	assert(datagramServer != NULL);
	assert(isNetworkInitialized() == true);
	return datagramServer->onReceive;
}

void* getDatagramServerHandle(DatagramServer datagramServer)
{
	assert(datagramServer != NULL);
	assert(isNetworkInitialized() == true);
	return datagramServer->handle;
}

Socket getDatagramServerSocket(DatagramServer datagramServer)
{
	assert(datagramServer != NULL);
	assert(isNetworkInitialized() == true);
	return datagramServer->socket;
}

bool updateDatagramServer(DatagramServer datagramServer)
{
	assert(datagramServer != NULL);

	uint8_t* receiveBuffer =
		datagramServer->receiveBuffer;

	size_t byteCount;

	bool result = socketReceiveFrom(
		datagramServer->socket,
		datagramServer->address,
		receiveBuffer,
		datagramServer->receiveBufferSize,
		&byteCount);

	if (result == false)
		return false;

	datagramServer->onReceive(
		datagramServer,
		datagramServer->address,
		receiveBuffer,
		byteCount);
	return true;
}

bool datagramServerSend(
	DatagramServer datagramServer,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress socketAddress)
{
	assert(datagramServer != NULL);
	assert(sendBuffer != NULL);
	assert(byteCount != 0);
	assert(socketAddress != NULL);
	assert(isNetworkInitialized() == true);

	return socketSendTo(
		datagramServer->socket,
		sendBuffer,
		byteCount,
		socketAddress);
}
