#include "mpnw/http.h"

struct HttpRequest
{
	uint8_t type;
	uint8_t version;
	char* uri;
};
struct HttpResponse
{
	uint8_t version;
	uint16_t status;
	uint8_t contentType;
	char* content;
	size_t contentLength;
};

char* serializeHttpRequest(
	uint8_t _type,
	const char* _uri,
	uint8_t _version,
	size_t* _size)
{
	assert(_uri != NULL);
	assert(_size != NULL);

	const char* type;
	size_t typeSize;

	if (_type == GET_HTTP_REQUEST)
	{
		type = "GET ";
		typeSize = 4;
	}
	else if (_type == POST_HTTP_REQUEST)
	{
		type = "POST ";
		typeSize = 5;
	}
	else
	{
		return NULL;
	}

	size_t uriSize = strlen(_uri);

	if (uriSize == 0)
		return  NULL;

	const char* version;
	size_t versionSize;

	if (_version == HTTP_10_VERSION)
	{
		version = " HTTP/1.0\r\n";
		versionSize = 11;
	}
	else if (_version == HTTP_11_VERSION)
	{
		version = " HTTP/1.1\r\n";
		versionSize = 11;
	}
	else
	{
		return NULL;
	}

	size_t size =
		typeSize +
		uriSize +
		versionSize + 2;

	char* data = malloc(
		size * sizeof(char));

	if (data == NULL)
		return NULL;

	size_t index = 0;

	memcpy(
		data + index,
		type,
		typeSize * sizeof(char));
	index += typeSize;

	memcpy(
		data + index,
		_uri,
		uriSize * sizeof(char));
	index += uriSize;

	memcpy(
		data + index,
		version,
		versionSize * sizeof(char));
	index += versionSize;

	memcpy(
		data + index,
		"\r\n",
		2 * sizeof(char));

	*_size = size;
	return data;
}

struct HttpRequest* deserializeHttpRequest(
	const char* data,
	size_t size)
{
	assert(data != NULL);
	assert(size != 0);

	if (size < 16)
		return NULL;

	struct HttpRequest* request = malloc(
		sizeof(struct HttpRequest));

	if (request == NULL)
		return NULL;

	size_t index = 0;
	uint8_t type;

	if (memcmp(data, "GET ", 4) == 0)
	{
		type = GET_HTTP_REQUEST;
		index += 4;
	}
	else if (memcmp(data, "POST ", 5) == 0)
	{
		type = POST_HTTP_REQUEST;
		index += 5;
	}
	else
	{
		free(request);
		return NULL;
	}

	size_t uriSize = 0;

	for (size_t i = index; i < size; i++)
	{
		if (data[i] == ' ')
		{
			uriSize = i - index;
			break;
		}
	}

	if (uriSize == 0)
	{
		free(request);
		return NULL;
	}

	char* uri = malloc(
		(uriSize + 1) * sizeof(char));

	if (uri == NULL)
	{
		free(request);
		return NULL;
	}

	uri[uriSize] = '\0';
	index += uriSize + 1;

	uint8_t version;

	if (size - index >= 10 &&
		memcmp(data + index, "HTTP/1.0\r\n", 10) == 0)
	{
		version = HTTP_10_VERSION;
		index += 10;
	}
	else if (size - index >= 10 &&
		memcmp(data + index, "HTTP/1.1\r\n", 10) == 0)
	{
		version = HTTP_11_VERSION;
		index += 10;
	}
	else
	{
		free(uri);
		free(request);
		return NULL;
	}

	if (type != HTTP_10_VERSION &&
		size - index == 2 &&
		memcmp(data + index, "\r\n", 2) == 0)
	{
		free(uri);
		free(request);
		return NULL;
	}

	request->type = type;
	request->uri = uri;
	request->version = version;
	return request;
}

void destroyHttpRequest(
	struct HttpRequest* request)
{
	if (request == NULL)
		return;

	free(request->uri);
	free(request);
}

uint8_t getHttpRequestType(
	const struct HttpRequest* request)
{
	assert(request != NULL);
	return request->type;
}

const char* getHttpRequestUri(
	const struct HttpRequest* request)
{
	assert(request != NULL);
	return request->uri;
}

uint8_t getHttpRequestVersion(
	const struct HttpRequest* request)
{
	assert(request != NULL);
	return request->version;
}

char* serializeHttpResponse(
	uint8_t _version,
	uint16_t _status,
	uint8_t _contentType,
	const char* content,
	size_t contentLength,
	size_t* _size)
{
	assert(_size != NULL);

	const char* version;
	size_t versionSize;

	if (_version == HTTP_10_VERSION)
	{
		version = "HTTP/1.0 ";
		versionSize = 9;
	}
	else if (_version == HTTP_11_VERSION)
	{
		version = "HTTP/1.1 ";
		versionSize = 9;
	}
	else
	{
		return NULL;
	}

	const char* status;
	size_t statusSize;

	switch (_status)
	{
	default:
		return NULL;
	case CONTINUE_HTTP_STATUS:
		status = "100 Continue\r\n";
		statusSize = 14;
		break;
	case OK_HTTP_STATUS:
		status = "200 OK\r\n";
		statusSize = 8;
		break;
	case MULTIPLE_CHOICE_HTTP_STATUS:
		status = "300 Multiple Choice\r\n";
		statusSize = 21;
		break;
	case BAD_REQUEST_HTTP_STATUS:
		status = "400 Bad Request\r\n";
		statusSize = 17;
		break;
	case UNAUTHORIZED_HTTP_STATUS:
		status = "401 Unauthorized\r\n";
		statusSize = 18;
		break;
	case FORBIDDEN_HTTP_STATUS:
		status = "403 Forbidden\r\n";
		statusSize = 15;
		break;
	case NOT_FOUND_HTTP_STATUS:
		status = "404 Not Found\r\n";
		statusSize = 15;
		break;
	case INTERNAL_SERVER_ERROR_HTTP_STATUS:
		status = "500 Internal Server Error\r\n";
		statusSize = 27;
		break;
	case NOT_IMPLEMENTED_HTTP_STATUS:
		status = "501 Not Implemented\r\n";
		statusSize = 21;
		break;
	}

	const char* contentType;
	size_t contentSize;

	if (content != NULL)
	{
		if (contentLength == 0)
			return NULL;

		if (_contentType == TEXT_HTML_HTTP_CONTENT)
		{
			contentType = "Content-Type: text/html; charset=UTF-8\r\n";
			contentSize = 40;
		}
		else
		{
			return NULL;
		}
	}
	else
	{
		contentSize = 0;
	}

	size_t size =
		versionSize +
		statusSize +
		contentSize +
		contentLength + 2;

	char* data = malloc(
		size * sizeof(char));

	if (data == NULL)
		return false;

	size_t index = 0;

	memcpy(
		data + index,
		version,
		versionSize * sizeof(char));
	index += versionSize;

	memcpy(
		data + index,
		status,
		statusSize * sizeof(char));
	index += statusSize;

	if (content != NULL)
	{
		memcpy(
			data + index,
			contentType,
			contentSize * sizeof(char));
		index += contentSize;
	}

	memcpy(
		data + index,
		"\r\n",
		2 * sizeof(char));
	index += 2;

	if (content != NULL)
	{
		memcpy(
			data + index,
			content,
			contentLength * sizeof(char));
	}

	*_size = size;
	return data;
}

struct HttpResponse* deserializeHttpResponse(
	const char* data,
	size_t size)
{
	assert(data != NULL);
	assert(size != 0);

	if (size < 19)
		return NULL;

	struct HttpResponse* response = malloc(
		sizeof(struct HttpResponse));

	if (response == NULL)
		return NULL;

	size_t index = 0;
	uint8_t version;

	if (memcmp(data, "HTTP/1.0", 8) == 0)
	{
		version = HTTP_10_VERSION;
		index += 9;
	}
	else if (memcmp(data, "HTTP/1.1", 8) == 0)
	{
		version = HTTP_11_VERSION;
		index += 9;
	}
	else
	{
		free(response);
		return NULL;
	}

	uint16_t status;

	if (size - index >= 14 &&
		memcmp(data + index, "100 Continue\r\n", 14) == 0)
	{
		status = CONTINUE_HTTP_STATUS;
		index += 14;
	}
	else if (size - index >= 8 &&
		memcmp(data + index, "200 OK\r\n", 8) == 0)
	{
		status = OK_HTTP_STATUS;
		index += 8;
	}
	else if (size - index >= 21 &&
		memcmp(data + index, "300 Multiple Choice\r\n", 21) == 0)
	{
		status = MULTIPLE_CHOICE_HTTP_STATUS;
		index += 21;
	}
	else if (size - index >= 17 &&
		memcmp(data + index, "400 Bad Request\r\n", 17) == 0)
	{
		status = BAD_REQUEST_HTTP_STATUS;
		index += 17;
	}
	else if (size - index >= 18 &&
		memcmp(data + index, "401 Unauthorized\r\n", 18) == 0)
	{
		status = UNAUTHORIZED_HTTP_STATUS;
		index += 18;
	}
	else if (size - index >= 15 &&
		memcmp(data + index, "403 Forbidden\r\n", 15) == 0)
	{
		status = FORBIDDEN_HTTP_STATUS;
		index += 15;
	}
	else if (size - index >= 15 &&
		memcmp(data + index, "404 Not Found\r\n", 15) == 0)
	{
		status = NOT_FOUND_HTTP_STATUS;
		index += 15;
	}
	else if (size - index >= 27 &&
		memcmp(data + index, "500 Internal Server Error\r\n", 27) == 0)
	{
		status = INTERNAL_SERVER_ERROR_HTTP_STATUS;
		index += 27;
	}
	else if (size - index >= 21 &&
		memcmp(data + index, "501 Not Implemented\r\n", 21) == 0)
	{
		status = NOT_IMPLEMENTED_HTTP_STATUS;
		index += 21;
	}
	else
	{
		free(response);
		return NULL;
	}

	uint16_t contentType = NONE_HTTP_CONTENT;

	while (true)
	{
		if (size - index >= 14 &&
			memcmp(data + index, "Content-Type: ", 14) == 0)
		{
			index += 14;

			if (size - index >= 26 &&
				memcmp(data + index, "text/html; charset=UTF-8\r\n", 26) == 0)
			{
				contentType = TEXT_HTML_HTTP_CONTENT;
				index += 26;
			}
		}
		else if (size - index >= 16 &&
			memcmp(data + index, "Transfer-Encoding: ", 16) == 0)
		{
			index += 16;

			// TODO: get content length
		}
		else
		{
			for (; index < size; index++)
			{
				if(data[index] == '\n' && data[index - 1] == '\r')
				{
					index++;
					goto END_HEADER;
				}
			}

			free(response);
			return NULL;
		}
	}
	
END_HEADER:

	if (size - index == 2 &&
		memcmp(data + index, "\r\n", 2) == 0)
	{
		free(response);
		return NULL;
	}

	// TODO: read data.

	response->version = version;
	response->status = status;
	response->contentType = contentType;
	return response;
}

void destroyHttpResponse(
	struct HttpResponse* response)
{
	if (response == NULL)
		return;

	free(response);
}

uint8_t getHttpResponseVersion(
	struct HttpResponse* response)
{
	assert(response != NULL);
	return response->version;
}

uint16_t getHttpResponseStatus(
	struct HttpResponse* response)
{
	assert(response != NULL);
	return response->status;
}

uint8_t getHttpResponseContentType(
	struct HttpResponse* response)
{
	assert(response != NULL);
	return response->contentType;
}

const char* getHttpResponseContent(
	struct HttpResponse* response)
{
	assert(response != NULL);
	return response->content;
}

size_t getHttpResponseContentLength(
	struct HttpResponse* response)
{
	assert(response != NULL);
	return response->contentLength;
}
