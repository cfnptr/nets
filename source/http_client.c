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

#include "mpmt/common.h"
#include "mpmt/thread.h"

#include <stdio.h>

struct HttpClient_T
{
	StreamClient handle;
	char* response;
	size_t responseSize;
	HttpHeader* headers;
	size_t headerCapacity;
	size_t headerCount;
	uint16_t statusCode;
	MpnwResult result;
	bool isRunning;
};

inline static MpnwResult processResponseLine(
	HttpClient httpClient,
	const char* line,
	size_t length)
{
	assert(httpClient);
	assert(line);
	assert(length > 0);

	if (httpClient->statusCode == 0)
	{
		if (length < 10 || memcmp(line, "HTTP/1.1 ", 9) != 0)
			return BAD_DATA_MPNW_RESULT;

		uint16_t statusCode = strtol(
			line + 9,
			NULL,
			10);

		if (statusCode == 0)
			return BAD_DATA_MPNW_RESULT;

		httpClient->statusCode = statusCode;
	}
	else
	{
		size_t keyLength = 0;

		for (size_t i = 0; i < length; i++)
		{
			char value = line[i];

			if (value == ':')
			{
				keyLength = i;
				break;
			}
		}

		if (keyLength == 0 || length < keyLength + 2)
			return BAD_DATA_MPNW_RESULT;

		size_t valueLength = length - (keyLength + 2);

		if (valueLength == 0)
			return BAD_DATA_MPNW_RESULT;

		char* key = malloc((keyLength + 1) * sizeof(char));

		if (!key)
			return OUT_OF_MEMORY_MPNW_RESULT;

		memcpy(key, line, keyLength);
		key[keyLength] = '\0';

		char* value = malloc((valueLength + 1) * sizeof(char));

		if (!value)
		{
			free(key);
			return OUT_OF_MEMORY_MPNW_RESULT;
		}

		memcpy(value, line + (length - valueLength), valueLength);
		value[valueLength] = '\0';

		if (httpClient->headerCount == httpClient->headerCapacity)
		{
			size_t capacity = httpClient->headerCapacity * 2;

			HttpHeader* newHeaders = realloc(
				httpClient->headers,
				capacity * sizeof(HttpHeader));

			if (!newHeaders)
			{
				free(value);
				free(key);
				return OUT_OF_MEMORY_MPNW_RESULT;
			}

			httpClient->headers = newHeaders;
			httpClient->headerCapacity = capacity;
		}

		HttpHeader header = {
			key, keyLength,
			value, valueLength
		};

		httpClient->headers[httpClient->headerCount++] = header;
	}

	return SUCCESS_MPNW_RESULT;
}
static void onStreamClientReceive(
	StreamClient streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount)
{
	assert(streamClient);
	assert(receiveBuffer);

	HttpClient httpClient = (HttpClient)
		getStreamClientHandle(streamClient);

	if (byteCount == 0)
	{
		httpClient->result = CONNECTION_IS_CLOSED_MPNW_RESULT;
		httpClient->isRunning = false;
		return;
	}

	const char* buffer = (const char*)receiveBuffer;
	size_t lineOffset = 0;

	for (size_t i = 0; i < byteCount; i++)
	{
		char value = buffer[i];

		if (value != '\n')
			continue;

		size_t lineLength = i - (lineOffset + 1);

		if (lineLength > 0)
		{
			MpnwResult mpnwResult = processResponseLine(
				httpClient,
				buffer + lineOffset,
				lineLength);

			if (mpnwResult != SUCCESS_MPNW_RESULT)
			{
				httpClient->result = mpnwResult;
				httpClient->isRunning = false;
				return;
			}
		}
		else
		{
			// TODO: sort received header, get content length and then receive data
		}

		lineOffset = i + 1;
	}

	if (lineOffset != byteCount)
	{
		// TODO: store to the buffer
	}

	printf("%s", receiveBuffer);
	httpClient->isRunning = false;
	httpClient->result = SUCCESS_MPNW_RESULT;
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

	httpClientInstance->statusCode = 0;
	httpClientInstance->result = SUCCESS_MPNW_RESULT;
	httpClientInstance->isRunning = false;

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

	char* response = malloc(
		receiveBufferSize * sizeof(char));

	if (!response)
	{
		destroyHttpClient(httpClientInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	httpClientInstance->response = response;
	httpClientInstance->responseSize = 0;

	HttpHeader* headers = malloc(
		MPNW_DEFAULT_CAPACITY * sizeof(HttpHeader));

	if (!headers)
	{
		destroyHttpClient(httpClientInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	httpClientInstance->headers = headers;
	httpClientInstance->headerCapacity = MPNW_DEFAULT_CAPACITY;
	httpClientInstance->headerCount = 0;

	*httpClient = httpClientInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroyHttpClient(HttpClient httpClient)
{
	if (!httpClient)
		return;

	HttpHeader* headers = httpClient->headers;

	if (headers)
	{
		size_t headerCount = httpClient->headerCount;

		for (size_t i = 0; i < headerCount; i++)
		{
			HttpHeader* header = &headers[i];
			free((char*)header->value);
			free((char*)headers->key);
		}

		free(headers);
	}

	free(httpClient->response);
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

	double time = getCurrentClock();

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
		remoteAddress,
		"voxfield.com"); // TODO: get hostname from the address

	destroySocketAddress(remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	setSocketNoDelay(
		getStreamClientSocket(streamClient),
		true);

	size_t pathLength = urlLength - pathOffset;
	size_t requestLength = pathLength + 18;

	if (headerCount > 0)
	{
		for (size_t i = 0; i < headerCount; i++)
		{
			const HttpHeader* header = &headers[i];
			requestLength += header->keyLength + header->valueLength + 4;
		}
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

	request[index + 0] = '\r';
	request[index + 1] = '\n';
	index += 2;

	assert(index == requestLength);

	mpnwResult = streamClientSend(
		streamClient,
		request,
		requestLength);

	free(request);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		disconnectStreamClient(streamClient);
		return mpnwResult;
	}

	httpClient->statusCode = 0;
	httpClient->result = TIMED_OUT_MPNW_RESULT;
	httpClient->isRunning = true;
	time += getStreamClientTimeoutTime(streamClient);

	while (httpClient->isRunning)
	{
		double currentTime = getCurrentClock();

		if (currentTime > time)
			break;

		updateStreamClient(streamClient);
		sleepThread(0.001);
	}

	disconnectStreamClient(streamClient);
	return httpClient->result;
}
