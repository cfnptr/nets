// Copyright 2020-2022 Nikita Fediuchin. All rights reserved.
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

struct DatagramServer_T
{
	size_t receiveBufferSize;
	OnDatagramServerReceive onReceive;
	void* handle;
	uint8_t* receiveBuffer;
	SocketAddress address;
	Socket socket;
};

MpnwResult createDatagramServer(
	AddressFamily addressFamily,
	const char* service,
	size_t receiveBufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* datagramServer)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(service);
	assert(receiveBufferSize > 0);
	assert(onReceive);
	assert(datagramServer);

	DatagramServer datagramServerInstance = calloc(
		1, sizeof(DatagramServer_T));

	if (!datagramServerInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	datagramServerInstance->onReceive = onReceive;
	datagramServerInstance->handle = handle;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (!receiveBuffer)
	{
		destroyDatagramServer(datagramServerInstance);
		return FAILED_TO_ALLOCATE_MPNW_RESULT;
	}

	datagramServerInstance->receiveBufferSize = receiveBufferSize;
	datagramServerInstance->receiveBuffer = receiveBuffer;

	MpnwResult mpnwResult;
	SocketAddress socketAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			service,
			&socketAddress);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		mpnwResult = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			service,
			&socketAddress);
	}
	else
	{
		abort();
	}

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyDatagramServer(datagramServerInstance);
		return mpnwResult;
	}

	datagramServerInstance->address = socketAddress;

	Socket socket;

	mpnwResult = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		socketAddress,
		false,
		NULL,
		&socket);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyDatagramServer(datagramServerInstance);
		return mpnwResult;
	}

	datagramServerInstance->socket = socket;

	*datagramServer = datagramServerInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyDatagramServer(DatagramServer datagramServer)
{
	if (!datagramServer)
		return;

	Socket socket = datagramServer->socket;

	if (socket)
	{
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	destroySocketAddress(datagramServer->address);
	free(datagramServer->receiveBuffer);
	free(datagramServer);
}

size_t getDatagramServerReceiveBufferSize(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->receiveBufferSize;
}
OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->onReceive;
}
void* getDatagramServerHandle(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->handle;
}
Socket getDatagramServerSocket(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->socket;
}

bool updateDatagramServer(DatagramServer datagramServer)
{
	assert(datagramServer);

	uint8_t* receiveBuffer =
		datagramServer->receiveBuffer;

	size_t byteCount;

	bool result = socketReceiveFrom(
		datagramServer->socket,
		datagramServer->address,
		receiveBuffer,
		datagramServer->receiveBufferSize,
		&byteCount);

	if (!result)
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
	SocketAddress remoteAddress)
{
	assert(datagramServer);
	assert(sendBuffer);
	assert(byteCount > 0);
	assert(remoteAddress);

	return socketSendTo(
		datagramServer->socket,
		sendBuffer,
		byteCount,
		remoteAddress);
}
