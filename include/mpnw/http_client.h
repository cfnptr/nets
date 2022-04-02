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

#pragma once
#include "mpnw/stream_client.h"

// ================================================
// Note: this is simple HTTP client implementation.
// ================================================

/*
 * HTTP client structure.
*/
typedef struct HttpClient_T HttpClient_T;
/*
 * HTTP client instance.
*/
typedef HttpClient_T* HttpClient;

typedef struct HttpHeader
{
	const char* key;
	size_t keyLength;
	const char* value;
	size_t valueLength;
} HttpHeader;

/*
 * Create a new HTTP client instance.
 * Returns operation MPNW result.
 *
 * receiveBufferSize - data and response buffer size.
 * timeoutTime - time out time. (seconds)
 * sslContext - SSL context instance or NULL.
 * httpClient - pointer to the HTTP client.
 */
MpnwResult creatHttpClient(
	size_t receiveBufferSize,
	double timeoutTime,
	SslContext sslContext,
	HttpClient* httpClient);
void destroyHttpClient(HttpClient httpClient);

/*
 * Returns HTTP client stream.
 * httpClient - HTTP client instance.
 */
StreamClient getHttpClientStream(HttpClient httpClient);

/*
 * Send HTTP GET request to the server.
 * Returns operation MPNW result.
 *
 * httpClient - HTTP client instance.
 * url - URL string.
 * urlLength - URL string length
 * addressFamily - address family type.
 * headers - HTTP headers or NULL.
 * headerCount - HTTP header count or 0.
 */
MpnwResult httpClientSendGET(
	HttpClient httpClient,
	const char* url,
	size_t urlLength,
	AddressFamily addressFamily,
	const HttpHeader* headers,
	size_t headerCount);

// TODO: shrink headers buffer
