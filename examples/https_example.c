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

#include "mpnw/stream_client.h"

#include "mpmt/thread.h"

#include <stdio.h>
#include <string.h>

#if !MPNW_SUPPORT_OPENSSL
#error OpenSSL is not supported
#endif

// This example receives not complete data from the host,
// to receive full data you need to parse HTTP header.

static void clientReceiveHandler(
	StreamClient streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	bool* isDataReceived =
		getStreamClientHandle(streamClient);
	*isDataReceived = true;

	if (byteCount == 0)
	{
		printf("Remote host has closed connection.\n");
	}
	else
	{
		printf("Received data: \n%.*s",
			(int)byteCount,
			receiveBuffer);
	}
}

int main()
{
	const char* hostName = "google.com";
	size_t receiveBufferSize = 8192;

	if (initializeNetwork() == false)
		return EXIT_FAILURE;

	SslContext sslContext;

	MpnwResult mpnwResult = createPublicSslContext(
		TLS_SECURITY_PROTOCOL,
		NULL,
		NULL,
		&sslContext);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("ERROR: %s.\n", mpnwResultToString(mpnwResult));
		return EXIT_FAILURE;
	}

	bool isDataReceived = false;

	StreamClient httpClient;

	mpnwResult = createStreamClient(
		IP_V4_ADDRESS_FAMILY,
		receiveBufferSize,
		clientReceiveHandler,
		&isDataReceived,
		sslContext,
		&httpClient);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("ERROR: %s.\n", mpnwResultToString(mpnwResult));
		return EXIT_FAILURE;
	}

	SocketAddress address;

	mpnwResult = resolveSocketAddress(
		hostName,
		"https",
		IP_V4_ADDRESS_FAMILY,
		STREAM_SOCKET_TYPE,
		&address);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("ERROR: %s.\n", mpnwResultToString(mpnwResult));
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

	printf("Resolved host name: %s:%s.\n",
		host,
		service);

	result = connectStreamClient(
		httpClient,
		address,
		2.0);

	destroySocketAddress(address);

	if (result == false)
	{
		printf("Failed to connect to the host.\n");
		return EXIT_FAILURE;
	}

	const char* request = "GET / HTTP/1.1\r\n\n\r\n";

	result = streamClientSend(
		httpClient,
		request,
		strlen(request));

	if (result == false)
	{
		printf("Failed to send request to the host.\n");
		return EXIT_FAILURE;
	}

	double timeout = getCurrentClock() + 2.0;

	while (getCurrentClock() < timeout)
	{
		if (isDataReceived == true)
			break;

		updateStreamClient(httpClient);
	}

	destroyStreamClient(httpClient);
	destroySslContext(sslContext);
	terminateNetwork();
	return EXIT_SUCCESS;
}
