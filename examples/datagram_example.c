#include "mpnw/datagram_server.h"
#include "mpnw/datagram_client.h"

#include "mpmt/thread.h"

#include <stdio.h>

static void serverReceiveHandler(
	struct DatagramServer* datagramServer,
	const struct SocketAddress* socketAddress,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	const char* serverName = (const char*)
		getDatagramServerFunctionArgument(datagramServer);

	if (byteCount != 1)
	{
		printf("%s: incorrect datagram size (%zu)\n",
			serverName,
			byteCount);
		fflush(stdout);
		return;
	}

	printf("%s: received request (%hhu)\n",
		serverName,
		receiveBuffer[0]);
	fflush(stdout);

	bool result = datagramServerSend(
		datagramServer,
		receiveBuffer,
		1,
		socketAddress);

	if (result == false)
	{
		printf("%s: failed to send response\n",
			serverName);
		fflush(stdout);
	}
}

static void clientReceiveHandler(
	struct DatagramClient* datagramClient,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	const char* clientName = (const char*)
		getDatagramClientFunctionArgument(datagramClient);

	if (byteCount != 1)
	{
		printf("%s: incorrect datagram size (%zu)\n",
			clientName,
			byteCount);
		fflush(stdout);
		return;
	}

	printf("%s: received response (%hhu)\n",
		clientName,
		receiveBuffer[0]);
	fflush(stdout);
}

int main()
{
	const char* serverPort = "12345";
	size_t receiveBufferSize = 4;

	if (initializeNetwork() == false)
		return EXIT_FAILURE;

	struct DatagramServer* server = createDatagramServer(
		IP_V4_ADDRESS_FAMILY,
		serverPort,
		receiveBufferSize,
		serverReceiveHandler,
		"Server",
		NULL);

	if (server == NULL)
		return EXIT_FAILURE;

	struct SocketAddress* serverAddress = createSocketAddress(
		LOOPBACK_IP_ADDRESS_V4,
		serverPort);

	if (serverAddress == NULL)
		return EXIT_FAILURE;

	struct DatagramClient* client = createDatagramClient(
		serverAddress,
		receiveBufferSize,
		clientReceiveHandler,
		"Client",
		NULL);

	destroySocketAddress(serverAddress);

	if (client == NULL)
		return EXIT_FAILURE;

	uint8_t message = 1;

	bool result = datagramClientSend(
		client,
		&message,
		sizeof(uint8_t));

	if (result == false)
		return EXIT_FAILURE;

	sleepThread(0.1);

	destroyDatagramClient(client);
	destroyDatagramServer(server);
	terminateNetwork();
	return EXIT_SUCCESS;
}
