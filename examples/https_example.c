#include "mpnw/stream_client.h"

#include "mpmt/thread.h"

#include <stdio.h>
#include <string.h>

static bool clientReceiveHandler(
	StreamClient* streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	if (byteCount == 0)
		return false;

	printf("Received data: \n%.*s",
		(int)byteCount,
		receiveBuffer);
	fflush(stdout);
	return true;
}

int main()
{
	const char* hostName = "google.com";
	size_t receiveBufferSize = 8192;

	if (initializeNetwork() == false)
		return EXIT_FAILURE;

	SslContext* sslContext = createSslContext(
		TLS_SECURITY_PROTOCOL,
		NULL);

	if (sslContext == NULL)
		return EXIT_FAILURE;

	StreamClient* httpClient = createStreamClient(
		IP_V4_ADDRESS_FAMILY,
		receiveBufferSize,
		clientReceiveHandler,
		NULL,
		sslContext);

	if (httpClient == NULL)
		return EXIT_FAILURE;

	SocketAddress* address = resolveSocketAddress(
		hostName,
		"https",
		IP_V4_ADDRESS_FAMILY,
		STREAM_SOCKET_TYPE);

	if (address == NULL)
	{
		printf("Failed to resolve host name\n");
		return EXIT_FAILURE;
	}

	char host[16];
	char service[6];

	bool result = getSocketAddressHostService(
		address,
		host,
		16,
		service,
		6);

	if (result == false)
		return EXIT_FAILURE;

	printf("Resolved host name: %s:%s\n",
		host,
		service);

	result = connectStreamClient(
		httpClient,
		address,
		2.0);

	destroySocketAddress(address);

	if (result == false)
	{
		printf("Failed to connect to the host\n");
		return EXIT_FAILURE;
	}

	const char* request = "GET / HTTP/1.1\r\n\n\r\n";

	result = streamClientSend(
		httpClient,
		request,
		strlen(request));

	if (result == false)
	{
		printf("Failed to send request to the host\n");
		return EXIT_FAILURE;
	}

	sleepThread(2.0);

	destroyStreamClient(httpClient);
	destroySslContext(sslContext);
	terminateNetwork();
	return EXIT_SUCCESS;
}
