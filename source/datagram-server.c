// Copyright 2020-2026 Nikita Fediuchin. All rights reserved.
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

#include "nets/datagram-server.h"
#include <string.h>

struct DatagramServer_T
{
	size_t bufferSize;
	OnDatagramServerReceive onReceive;
	void* handle;
	uint8_t* buffer;
	SocketAddress address;
	Socket socket;
};

//**********************************************************************************************************************
NetsResult createDatagramServer(SocketFamily socketFamily, const char* service, size_t bufferSize,
	OnDatagramServerReceive onReceive, void* handle, DatagramServer* datagramServer)
{
	assert(socketFamily < SOCKET_FAMILY_COUNT);
	assert(service);
	assert(strlen(service) > 0);
	assert(bufferSize > 0);
	assert(onReceive);
	assert(datagramServer);

	DatagramServer datagramServerInstance = calloc(1, sizeof(DatagramServer_T));
	if (!datagramServerInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	datagramServerInstance->onReceive = onReceive;
	datagramServerInstance->handle = handle;

	uint8_t* receiveBuffer = malloc(bufferSize * sizeof(uint8_t));
	if (!receiveBuffer)
	{
		destroyDatagramServer(datagramServerInstance);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	datagramServerInstance->buffer = receiveBuffer;
	datagramServerInstance->bufferSize = bufferSize;

	SocketAddress socketAddress;
	NetsResult netsResult = createSocketAddress(socketFamily == IP_V4_SOCKET_FAMILY ?
		ANY_IP_ADDRESS_V4 : ANY_IP_ADDRESS_V6, service, &socketAddress);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroyDatagramServer(datagramServerInstance);
		return netsResult;
	}
	datagramServerInstance->address = socketAddress;

	Socket socket;
	netsResult = createSocket(DATAGRAM_SOCKET_TYPE, socketFamily, socketAddress, false, false, NULL, &socket);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroyDatagramServer(datagramServerInstance);
		return netsResult;
	}

	datagramServerInstance->socket = socket;
	*datagramServer = datagramServerInstance;
	return SUCCESS_NETS_RESULT;
}
void destroyDatagramServer(DatagramServer datagramServer)
{
	if (!datagramServer)
		return;

	if (datagramServer->socket)
	{
		Socket socket = datagramServer->socket;
		shutdownSocket(socket, RECEIVE_SEND_SOCKET_SHUTDOWN);
		destroySocket(socket);
	}

	destroySocketAddress(datagramServer->address);
	free(datagramServer->buffer);
	free(datagramServer);
}

//**********************************************************************************************************************
size_t getDatagramServerBufferSize(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->bufferSize;
}
uint8_t* getDatagramServerBuffer(DatagramServer datagramServer)
{
	assert(datagramServer);
	return datagramServer->buffer;
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

NetsResult updateDatagramServer(DatagramServer datagramServer)
{
	assert(datagramServer);
	uint8_t* receiveBuffer = datagramServer->buffer;

	size_t byteCount;
	NetsResult netsResult = socketReceiveFrom(datagramServer->socket, 
		datagramServer->address, receiveBuffer, datagramServer->bufferSize, &byteCount);
	if (netsResult != SUCCESS_NETS_RESULT)
		return netsResult;

	datagramServer->onReceive(datagramServer, datagramServer->address, receiveBuffer, byteCount);
	return SUCCESS_NETS_RESULT;
}

NetsResult datagramServerSend(DatagramServer datagramServer, 
	const void* data, size_t byteCount, SocketAddress remoteAddress)
{
	assert(datagramServer);
	return socketSendTo(datagramServer->socket, data, byteCount, remoteAddress);
}