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
#include "mpnw/datagram_client.h"

#include "mpmt/thread.h"
#include <stdio.h>

#define SERVER_PORT "12345"
#define RECEIVE_BUFFER_SIZE 4

typedef struct Server
{
	DatagramServer server;
	Thread thread;
	volatile bool isRunning;
} Server;

typedef struct Client
{
	DatagramClient client;
	Thread thread;
	volatile bool isRunning;
} Client;

static void onServerReceive(
	DatagramServer server,
	SocketAddress address,
	const uint8_t* buffer,
	size_t byteCount)
{
	if (byteCount != 1)
	{
		printf("[SERVER]: Incorrect datagram size. "
			"(%zu)\n", byteCount);
		fflush(stdout);
		return;
	}

	printf("[SERVER]: Received request. "
		"(value: %hhu)\n", buffer[0]);
	fflush(stdout);

	MpnwResult mpnwResult = datagramServerSend(
		server,
		buffer,
		1,
		address);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("[SERVER]: Failed to send response. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		fflush(stdout);
	}
}
static void serverHandler(void* argument)
{
#if __linux__ || __APPLE__
	disableSigpipe();
#endif

	Server* server = (Server*)argument;

	while (server->isRunning)
	{
		MpnwResult mpnwResult = updateDatagramServer(
			server->server);

		if (mpnwResult != SUCCESS_MPNW_RESULT)
			sleepThread(0.001);
	}
}

inline static Server* createServer()
{
	Server* server = malloc(sizeof(Server));

	if (server == NULL)
		return NULL;

	DatagramServer datagramServer;

	MpnwResult mpnwResult = createDatagramServer(
		IP_V4_ADDRESS_FAMILY,
		SERVER_PORT,
		RECEIVE_BUFFER_SIZE,
		onServerReceive,
		NULL,
		&datagramServer);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to create datagram server. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		free(server);
		return NULL;
	}

	server->server = datagramServer;
	server->isRunning = true;

	Thread thread = createThread(
		serverHandler,
		server);

	if (thread == NULL)
	{
		printf("Failed to create server thread.\n");
		destroyDatagramServer(datagramServer);
		free(server);
		return NULL;
	}

	server->thread = thread;
	return server;
}
inline static void destroyServer(Server* server)
{
	if (server == NULL)
		return;

	server->isRunning = false;
	joinThread(server->thread);
	destroyThread(server->thread);
	destroyDatagramServer(server->server);
	free(server);
}

static void onClientReceive(
	DatagramClient client,
	const uint8_t* buffer,
	size_t byteCount)
{
	if (byteCount != 1)
	{
		printf("[CLIENT]: Incorrect datagram size. "
			"(%zu).\n", byteCount);
		fflush(stdout);
		return;
	}

	printf("[CLIENT]: Received response. "
		"(value: %hhu).\n", buffer[0]);
	fflush(stdout);
}
static void clientHandler(void* argument)
{
#if __linux__ || __APPLE__
	disableSigpipe();
#endif

	Client* client = (Client*)argument;

	while (client->isRunning)
	{
		MpnwResult mpnwResult = updateDatagramClient(
			client->client);

		if (mpnwResult == SUCCESS_MPNW_RESULT)
		{
			continue;
		}
		else if (mpnwResult == IN_PROGRESS_MPNW_RESULT)
		{
			sleepThread(0.001);
			continue;
		}

		printf("[CLIENT]: Failed to update client. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		fflush(stdout);
		client->isRunning = false;
		return;
	}
}

inline static Client* createClient()
{
	Client* client = malloc(sizeof(Client));

	if (client == NULL)
		return NULL;

	SocketAddress remoteAddress;

	MpnwResult mpnwResult = createSocketAddress(
		LOOPBACK_IP_ADDRESS_V4,
		SERVER_PORT,
		&remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to create client socket address. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		free(client);
		return NULL;
	}

	DatagramClient datagramClient;

	mpnwResult = createDatagramClient(
		remoteAddress,
		RECEIVE_BUFFER_SIZE,
		onClientReceive,
		NULL,
		&datagramClient);

	destroySocketAddress(remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to create datagram client. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		free(client);
		return NULL;
	}

	client->client = datagramClient;
	client->isRunning = true;

	Thread thread = createThread(
		clientHandler,
		client);

	if (thread == NULL)
	{
		printf("Failed to create client thread.\n");
		destroyDatagramClient(datagramClient);
		free(client);
		return NULL;
	}

	client->thread = thread;
	return client;
}
inline static void destroyClient(Client* client)
{
	if (client == NULL)
		return;

	client->isRunning = false;
	joinThread(client->thread);
	destroyThread(client->thread);
	destroyDatagramClient(client->client);
	free(client);
}

int main()
{
	if (initializeNetwork() == false)
	{
		printf("Failed to initialize network.\n");
		return EXIT_FAILURE;
	}

	Server* server = createServer();

	if (server == NULL)
	{
		terminateNetwork();
		return EXIT_FAILURE;
	}

	Client* client = createClient();

	if (client == NULL)
	{
		destroyServer(server);
		terminateNetwork();
		return EXIT_FAILURE;
	}

	uint8_t message = 1;

	MpnwResult mpnwResult = datagramClientSend(
		client->client,
		&message,
		sizeof(uint8_t));

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to send client datagram. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		destroyClient(client);
		destroyServer(server);
		terminateNetwork();
		return EXIT_FAILURE;
	}

	sleepThread(0.1);

	destroyClient(client);
	destroyServer(server);
	terminateNetwork();
	return EXIT_SUCCESS;
}
