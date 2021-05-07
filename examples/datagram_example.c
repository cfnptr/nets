#include "mpnw/datagram_server.h"
#include "mpnw/datagram_client.h"

#include "mpmt/thread.h"
#include <stdio.h>

#define SERVER_PORT "12345"
#define RECEIVE_BUFFER_SIZE 4


typedef struct Server
{
	DatagramServer* server;
	Thread* thread;
	volatile bool isRunning;
} Server;

typedef struct Client
{
	DatagramClient* client;
	Thread* thread;
	volatile bool isRunning;
} Client;

static void onServerReceive(
	DatagramServer* server,
	const SocketAddress* address,
	const uint8_t* buffer,
	size_t byteCount)
{
	if (byteCount != 1)
	{
		printf("Server: incorrect datagram size (%zu)\n",
			byteCount);
		fflush(stdout);
		return;
	}

	printf("Server: received request (%hhu)\n",
		buffer[0]);
	fflush(stdout);

	bool result = datagramServerSend(
		server,
		buffer,
		1,
		address);

	if (result == false)
	{
		printf("Server: failed to send response\n");
		fflush(stdout);
	}
}
static void serverHandler(void* argument)
{
	Server* server = (Server*)argument;

	while (server->isRunning == true)
	{
		bool result = updateDatagramServer(
			server->server);

		if (result == false)
			sleepThread(0.001);
	}
}

inline static Server* createServer()
{
	Server* server = malloc(sizeof(Server));

	if (server == NULL)
		return NULL;

	DatagramServer* datagramServer = createDatagramServer(
		IP_V4_ADDRESS_FAMILY,
		SERVER_PORT,
		RECEIVE_BUFFER_SIZE,
		onServerReceive,
		NULL);

	if (datagramServer == NULL)
	{
		free(server);
		return NULL;
	}

	server->server = datagramServer;
	server->isRunning = true;

	Thread* thread = createThread(
		serverHandler,
		server);

	if (thread == NULL)
	{
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
	DatagramClient* client,
	const uint8_t* buffer,
	size_t byteCount)
{
	if (byteCount != 1)
	{
		printf("Client: incorrect datagram size (%zu)\n",
			byteCount);
		fflush(stdout);
		return;
	}

	printf("Client: received response (%hhu)\n",
		buffer[0]);
	fflush(stdout);
}
static void clientHandler(void* argument)
{
	Client* client = (Client*)argument;

	while (client->isRunning == true)
	{
		bool result = updateDatagramClient(
			client->client);

		if (result == false)
			sleepThread(0.001);
	}
}

inline static Client* createClient()
{
	Client* client = malloc(sizeof(Client));

	if (client == NULL)
		return NULL;

	SocketAddress* remoteAddress = createSocketAddress(
		LOOPBACK_IP_ADDRESS_V4,
		SERVER_PORT);

	if (remoteAddress == NULL)
	{
		free(client);
		return NULL;
	}

	DatagramClient* datagramClient = createDatagramClient(
		remoteAddress,
		RECEIVE_BUFFER_SIZE,
		onClientReceive,
		NULL);

	destroySocketAddress(remoteAddress);

	if (datagramClient == NULL)
	{
		free(client);
		return NULL;
	}

	client->client = datagramClient;
	client->isRunning = true;

	Thread* thread = createThread(
		clientHandler,
		client);

	if (thread == NULL)
	{
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
		return EXIT_FAILURE;

	Server* server = createServer();

	if (server == NULL)
		return EXIT_FAILURE;

	Client* client = createClient();

	if (client == NULL)
		return EXIT_FAILURE;

	uint8_t message = 1;

	bool result = datagramClientSend(
		client->client,
		&message,
		sizeof(uint8_t));

	if (result == false)
		return EXIT_FAILURE;

	sleepThread(0.1);

	destroyClient(client);
	destroyServer(server);
	terminateNetwork();
	return EXIT_SUCCESS;
}
