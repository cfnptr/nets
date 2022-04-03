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
#include <ctype.h>

struct HttpClient_T
{
	size_t responseBufferSize;
	size_t headerBufferSize;
	SocketAddress address;
	StreamClient handle;
	char* response;
	HttpHeader* headers;
	size_t chunkSize;
	size_t responseLength;
	size_t headerCount;
	uint16_t statusCode;
	bool isBody;
	bool isChunked;
	MpnwResult result;
	bool isRunning;
};

static int cmpHttpHeaders(const void* a, const void* b)
{
	const HttpHeader* ah = (const HttpHeader*)a;
	const HttpHeader* bh = (const HttpHeader*)b;

	int difference = ah->keyLength - bh->keyLength;

	if (difference != 0)
		return difference;

	const char* ak = ah->key;
	const char* bk = ah->key;
	int length = ah->keyLength;

	for (int i = 0; i < length; i++)
	{
		difference = tolower(ak[i]) - tolower(bk[i]);

		if (difference != 0)
			return difference;
	}

	return 0;
}

inline static MpnwResult processResponseLine(
	HttpClient httpClient,
	const char* line,
	size_t length)
{
	assert(httpClient);
	assert(line);

	if (length == 0)
	{
		qsort(httpClient->headers,
			httpClient->headerCount,
			sizeof(HttpHeader),
			cmpHttpHeaders);

		const char* contentLength = getHttpClientHeader(
			httpClient,
			"Content-Length",
			14);

		if (contentLength)
		{
			int64_t responseLength = (int64_t)strtol(
				contentLength,
				NULL,
				10);

			if (responseLength == 0)
				return SUCCESS_MPNW_RESULT;
			if (responseLength < 0)
				return BAD_DATA_MPNW_RESULT;

			httpClient->responseLength = responseLength;
		}
		else
		{
			const char* transferEncoding = getHttpClientHeader(
				httpClient,
				"Transfer-Encoding",
				17);

			if (!transferEncoding ||
				memcmp(transferEncoding, "chunked", 7) != 0)
			{
				// TODO: support compression
				return BAD_DATA_MPNW_RESULT;
			}

			httpClient->isChunked = true;
		}

		httpClient->isBody = true;
		return SUCCESS_MPNW_RESULT;
	}

	if (httpClient->statusCode == 0)
	{
		if (length < 10 || memcmp(line, "HTTP/1.1 ", 9) != 0)
			return BAD_DATA_MPNW_RESULT;

		uint16_t statusCode = (uint16_t)strtol(
			line + 9,
			NULL,
			10);

		if (statusCode == 0)
			return BAD_DATA_MPNW_RESULT;

		httpClient->statusCode = statusCode;
	}
	else if (httpClient->isChunked == false)
	{
		if (httpClient->headerCount == httpClient->headerBufferSize)
			return OUT_OF_MEMORY_MPNW_RESULT;

		int keyLength = 0;

		for (size_t i = 0; i < length; i++)
		{
			char value = line[i];

			if (value == ':')
			{
				keyLength = (int)i;
				break;
			}
		}

		if (keyLength == 0 || length < keyLength + 2)
			return BAD_DATA_MPNW_RESULT;

		int valueLength = (int)(length - (keyLength + 2));

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

		HttpHeader header = {
			key, value,
			keyLength, valueLength
		};

		httpClient->headers[httpClient->headerCount++] = header;
	}
	else
	{
		int64_t chunkSize = (int64_t)strtol(
			line,
			NULL,
			16);

		if (chunkSize == 0)
			return SUCCESS_MPNW_RESULT;
		if (chunkSize < 0)
			return BAD_DATA_MPNW_RESULT;

		httpClient->chunkSize = chunkSize;
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

	if (httpClient->isBody == true)
	{
		// TODO: read chunkdata until zero
	}

	for (size_t i = 0; i < byteCount; i++)
	{
		char value = buffer[i];

		if (value != '\n')
			continue;

		if (lineOffset + 1 > i)
		{
			httpClient->result = BAD_DATA_MPNW_RESULT;
			httpClient->isRunning = false;
			return;
		}

		size_t length = i - (lineOffset + 1);

		if (httpClient->responseLength > 0)
		{
			size_t responseLength = httpClient->responseLength;

			if (responseLength + length > httpClient->responseBufferSize)
			{
				httpClient->result = OUT_OF_MEMORY_MPNW_RESULT;
				httpClient->isRunning = false;
				return;
			}

			char* response = httpClient->response;

			memcpy(response + responseLength,
				receiveBuffer, length);

			MpnwResult mpnwResult = processResponseLine(
				httpClient,
				response,
				responseLength + length);

			if (mpnwResult != SUCCESS_MPNW_RESULT)
			{
				httpClient->result = mpnwResult;
				httpClient->isRunning = false;
				return;
			}

			httpClient->responseLength = 0;
		}
		else
		{
			MpnwResult mpnwResult = processResponseLine(
				httpClient,
				buffer + lineOffset,
				length);

			if (mpnwResult != SUCCESS_MPNW_RESULT)
			{
				httpClient->result = mpnwResult;
				httpClient->isRunning = false;
				return;
			}
		}

		lineOffset = i + 1;
	}

	if (lineOffset != byteCount)
	{
		size_t count = byteCount - lineOffset;
		size_t responseLength = httpClient->responseLength;

		if (responseLength + count > httpClient->responseBufferSize)
		{
			httpClient->result = OUT_OF_MEMORY_MPNW_RESULT;
			httpClient->isRunning = false;
			return;
		}

		memcpy(httpClient->response + responseLength,
			receiveBuffer + lineOffset, count);
		httpClient->responseLength += count;
	}
}

MpnwResult creatHttpClient(
	size_t dataBufferSize,
	size_t responseBufferSize,
	size_t headerBufferSize,
	double timeoutTime,
	SslContext sslContext,
	HttpClient* httpClient)
{
	assert(dataBufferSize > 0);
	assert(responseBufferSize > 0);
	assert(timeoutTime > 0.0);
	assert(httpClient);

	HttpClient httpClientInstance = calloc(
		1, sizeof(HttpClient_T));

	if (!httpClientInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	httpClientInstance->chunkSize = 0;
	httpClientInstance->responseLength = 0;
	httpClientInstance->headerCount = 0;
	httpClientInstance->statusCode = 0;
	httpClientInstance->isBody = false;
	httpClientInstance->isChunked = false;
	httpClientInstance->result = SUCCESS_MPNW_RESULT;
	httpClientInstance->isRunning = false;

	SocketAddress address;

	MpnwResult mpnwResult = createAnySocketAddress(
		IP_V4_ADDRESS_FAMILY,
		&address);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroyHttpClient(httpClientInstance);
		return mpnwResult;
	}

	httpClientInstance->address = address;

	StreamClient handle;

	mpnwResult = createStreamClient(
		dataBufferSize,
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
		responseBufferSize * sizeof(char));

	if (!response)
	{
		destroyHttpClient(httpClientInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	httpClientInstance->response = response;
	httpClientInstance->responseBufferSize = responseBufferSize;

	HttpHeader* headers = malloc(
		headerBufferSize * sizeof(HttpHeader));

	if (!headers)
	{
		destroyHttpClient(httpClientInstance);
		return OUT_OF_MEMORY_MPNW_RESULT;
	}

	httpClientInstance->headers = headers;
	httpClientInstance->headerBufferSize = headerBufferSize;

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
			const HttpHeader* header = &headers[i];
			free((char*)header->value);
			free((char*)headers->key);
		}

		free(headers);
	}

	free(httpClient->response);
	destroyStreamClient(httpClient->handle);
	destroySocketAddress(httpClient->address);
	free(httpClient);
}

size_t getHttpResponseBufferSize(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->responseBufferSize;
}
size_t getHttpHeaderBufferSize(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->headerBufferSize;
}
StreamClient getHttpClientStream(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->handle;
}
int getHttpClientStatusCode(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->statusCode;
}
const char* getHttpClientResponse(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->response;
}
size_t getHttpClientResponseLength(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->responseLength;
}
const HttpHeader* getHttpClientHeaders(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->headers;
}
size_t getHttpClientHeaderCount(HttpClient httpClient)
{
	assert(httpClient);
	return httpClient->headerCount;
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

	char* host;
	size_t hostLength;
	char* service;
	size_t serviceLength;
	size_t pathOffset;

	// TODO: possibly cache, use url length as target size
	MpnwResult mpnwResult = allocateUrlHostService(
		url,
		urlLength,
		&host,
		&hostLength,
		&service,
		&serviceLength,
		&pathOffset);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
		return mpnwResult;

	SocketAddress remoteAddress = httpClient->address;

	mpnwResult = resolveSocketAddress(
		host,
		service ? service : (sslContext ? "https" : "http"),
		addressFamily,
		STREAM_SOCKET_TYPE,
		remoteAddress);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(service);
		free(host);
		return mpnwResult;
	}

	mpnwResult = connectStreamClient(
		streamClient,
		remoteAddress,
		host);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		free(service);
		free(host);
		return mpnwResult;
	}

	setSocketNoDelay(
		getStreamClientSocket(streamClient),
		true);

	size_t pathLength = urlLength - pathOffset;
	size_t requestLength = pathLength + hostLength + 26;

	if (headerCount > 0)
	{
		for (size_t i = 0; i < headerCount; i++)
		{
			const HttpHeader* header = &headers[i];
			requestLength += header->keyLength + header->valueLength + 4;
		}
	}

	if (requestLength > getStreamClientBufferSize(streamClient))
		return OUT_OF_MEMORY_MPNW_RESULT;

	char* request = (char*)getStreamClientBuffer(streamClient);

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
	request[index + 11] = 'H';
	request[index + 12] = 'o';
	request[index + 13] = 's';
	request[index + 14] = 't';
	request[index + 15] = ':';
	request[index + 16] = ' ';
	index += 17;

	memcpy(request + index, host, hostLength);
	index += hostLength;

	free(service);
	free(host);

	request[index + 0] = '\r';
	request[index + 1] = '\n';
	index += 2;

	if (headerCount > 0)
	{
		for (size_t i = 0; i < headerCount; i++)
		{
			HttpHeader header = headers[i];
			memcpy(request + index, header.key, header.keyLength);

			index += header.keyLength;
			request[index + 0] = ':';
			request[index + 1] = ' ';
			index += 2;

			memcpy(request + index, header.value, header.valueLength);
			index += header.valueLength;

			request[index + 0] = '\r';
			request[index + 1] = '\n';
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

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		disconnectStreamClient(streamClient);
		return mpnwResult;
	}

	HttpHeader* headerBuffer = httpClient->headers;
	size_t headerBufferSize = httpClient->headerCount;

	for (size_t i = 0; i < headerBufferSize; i++)
	{
		const HttpHeader* header = &headerBuffer[i];
		free((char*)header->value);
		free((char*)header->key);
	}

	httpClient->chunkSize = 0;
	httpClient->responseLength = 0;
	httpClient->headerCount = 0;
	httpClient->statusCode = 0;
	httpClient->isBody = false;
	httpClient->isChunked = false;
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

const char* getHttpClientHeader(
	HttpClient httpClient,
	const char* key,
	int length)
{
	assert(httpClient);
	assert(key);
	assert(length > 0);

	HttpHeader searchHeader = {
		key, NULL,
		length, 0,
	};

	HttpHeader* header = bsearch(
		&searchHeader,
		httpClient->headers,
		httpClient->headerCount,
		sizeof(HttpHeader),
		cmpHttpHeaders);

	if (!header)
		return NULL;

	return header->value;
}
