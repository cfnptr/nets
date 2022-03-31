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

struct HttpClient_T
{
	StreamClient handle;
};

static void onStreamClientReceive(
	StreamClient streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	assert(streamClient);
	assert(receiveBuffer);

	HttpClient httpClient = (HttpClient)
		getStreamClientHandle(streamClient);


}

MpnwResult creatHttpClient(
	size_t receiveBufferSize,
	double timeoutTime,
	SslContext sslContext,
	HttpClient* httpClient)
{
	assert(receiveBufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(httpClient);

	HttpClient httpClientInstance = calloc(
		1, sizeof(HttpClient_T));

	if (!httpClientInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	StreamClient handle;

	MpnwResult mpnwResult = createStreamClient(
		receiveBufferSize,
		timeoutTime,
		onStreamClientReceive,
		httpClientInstance,
		sslContext,
		&handle);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyHttpClient(httpClientInstance);
		return mpnwResult;
	}

	httpClientInstance->handle = handle;

	// TODO: set nodelay

	*httpClient = httpClientInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyHttpClient(HttpClient httpClient)
{
	if (!httpClient)
		return;

	destroyStreamClient(httpClient->handle);
	free(httpClient);
}

StreamClient getHttpClientStream(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->handle;
}

MpnwResult httpClientSendGET(
	HttpClient httpClient,
	const char* url,
	size_t urlLength,
	AddressFamily addressFamily,
	const HttpHeader* headers,
	size_t headerCount)
{
	assert(httpClient);
	assert(url);
	assert(urlLength > 0);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);

	assert((headers && headerCount > 0) ||
		(!headers && headerCount == 0));

#ifndef NDEBUG
	for (size_t i = 0; i < headerCount; i++)
	{
		HttpHeader header = headers[i];
		assert(header.key);
		assert(header.keyLength > 0);
		assert(header.value);
		assert(header.valueLength > 0);
	}
#endif

	StreamClient streamClient = httpClient->handle;
	SslContext sslContext = getStreamClientSslContext(streamClient);

	SocketAddress remoteAddress;
	size_t pathOffset;

	MpnwResult mpnwResult = resolveUrlSocketAddress(
		url,
		urlLength,
		addressFamily,
		STREAM_SOCKET_TYPE,
		sslContext ? "https" : "http",
		&pathOffset,
		&remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	mpnwResult = connectStreamClient(
		streamClient,
		remoteAddress);

	destroySocketAddress(remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	size_t pathLength = urlLength - pathOffset;
	size_t requestLength = pathLength + 16;

	if (headerCount > 0)
	{
		for (size_t i = 0; i < headerCount; i++)
		{
			const HttpHeader* header = &headers[i];
			requestLength += header->keyLength + header->valueLength + 4;
		}
	}
	else
	{
		requestLength += 3;
	}

	char* request = malloc(requestLength);
	// TODO: possibly cache request buffer or create in constructor.

	if (!request)
		return OUT_OF_MEMORY_MPNW_RESULT;

	request[0] = 'G';
	request[1] = 'E';
	request[2] = 'T';
	request[3] = ' ';
	request[4] = '/';
	size_t index = 5;

	if (pathLength > 0)
	{
		memcpy(request + index, url + pathOffset, pathLength);
		index += pathLength;
	}

	request[index + 0] = ' ';
	request[index + 1] = 'H';
	request[index + 2] = 'T';
	request[index + 3] = 'T';
	request[index + 4] = 'P';
	request[index + 5] = '/';
	request[index + 6] = '1';
	request[index + 7] = '.';
	request[index + 8] = '1';
	request[index + 9] = '\r';
	request[index + 10] = '\n';
	index += 11;

	if (headerCount > 0)
	{
		for (size_t i = 0; i < headerCount; i++)
		{
			HttpHeader header = headers[i];
			memcpy(request + index, header.key, header.keyLength);

			index += header.keyLength;
			request[index + 1] = ':';
			request[index + 2] = ' ';
			index += 2;

			memcpy(request + index, header.value, header.valueLength);
			index += header.valueLength;

			request[index + 1] = '\r';
			request[index + 2] = '\n';
			index += 2;
		}
	}
	else
	{
		request[index + 0] = '\n';
		request[index + 1] = '\r';
		request[index + 2] = '\n';
		index += 3;
	}

	assert(index == requestLength);

	bool result = streamClientSend(
		streamClient,
		request,
		requestLength);

	free(request);

	if (!result)
	{
		disconnectStreamClient(streamClient);
		return lastErrorToMpnwResult();
	}

	// TODO: wait for response or timeout,
	//  also take into account connect consumed time

	disconnectStreamClient(streamClient);
	return SUCCESS_MPNW_RESULT;
}
