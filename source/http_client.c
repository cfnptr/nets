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
	const char* uri,
	size_t uriLength,
	AddressFamily addressFamily)
{
	assert(httpClient);
	assert(uri);
	assert(uriLength > 0);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);

	StreamClient streamClient = httpClient->handle;
	SslContext sslContext = getStreamClientSslContext(streamClient);

	SocketAddress remoteAddress;
	size_t pathOffset;

	MpnwResult mpnwResult = resolveUriSocketAddress(
		uri,
		uriLength,
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

	const char* requestHeader = "GET /%.*s HTTP/1.1\r\n";

	size_t pathLength = uriLength - pathOffset;
	size_t requestLength = strlen(requestHeader) + pathLength;
	char* request = malloc(requestLength);

	if (!request)
		return OUT_OF_MEMORY_MPNW_RESULT;

	sprintf(request, requestHeader,
		pathLength, uri + pathOffset);

	bool result = streamClientSend(
		streamClient,
		request,
		requestLength);

	if (!result)

}
