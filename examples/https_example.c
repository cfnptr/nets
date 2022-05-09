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

#include "mpnw/http_client.h"
#include <stdio.h>

#if !MPNW_SUPPORT_OPENSSL
#error OpenSSL is not supported
#endif

#define DATA_BUFFER_SIZE 2048
#define RESPONSE_BUFFER_SIZE 65536
#define HEADER_BUFFER_SIZE 16
#define TIMEOUT_TIME 2.0
#define REQUEST_URL "www.google.com"

int main()
{
	if (initializeNetwork() == false)
	{
		printf("Failed to initialize network.\n");
		return EXIT_FAILURE;
	}

	SslContext sslContext;

	MpnwResult mpnwResult = createPublicSslContext(
		TLS_SECURITY_PROTOCOL,
		NULL,
		NULL,
		&sslContext);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to create SSL context. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		terminateNetwork();
		return EXIT_FAILURE;
	}

	HttpClient httpClient;

	mpnwResult = createHttpClient(
		DATA_BUFFER_SIZE,
		RESPONSE_BUFFER_SIZE,
		HEADER_BUFFER_SIZE,
		TIMEOUT_TIME,
		true,
		sslContext,
		&httpClient);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to create HTTP client. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		destroySslContext(sslContext);
		terminateNetwork();
		return EXIT_FAILURE;
	}

	mpnwResult = httpClientSendGET(
		httpClient,
		REQUEST_URL,
		strlen(REQUEST_URL),
		NULL,
		0,
		false);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		printf("Failed to get page. (error: %s)\n",
			mpnwResultToString(mpnwResult));
		destroyHttpClient(httpClient);
		destroySslContext(sslContext);
		terminateNetwork();
		return EXIT_FAILURE;
	}

	printf("RESPONSE:\n\n%.*s",
		(int)getHttpClientResponseLength(httpClient),
		getHttpClientResponse(httpClient));

	destroyHttpClient(httpClient);
	destroySslContext(sslContext);
	terminateNetwork();
	return EXIT_SUCCESS;
}
