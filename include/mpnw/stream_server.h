#pragma once
#include "mpnw/socket.h"

#include <assert.h>
#include <string.h>

/* Stream server instance handle (TCP) */
struct StreamServer;
/* Stream server session instance handle (TCP) */
struct StreamSession;

/* Stream session message receive function */
typedef bool(*StreamSessionReceive)(
	struct StreamServer* streamServer,
	struct StreamSession* streamSession,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/* Stream session create function */
typedef bool(*StreamSessionCreate)(
	struct StreamServer* streamServer,
	struct Socket* streamSocket,
	void** sessionHandle);

/* Stream session destroy function */
typedef void(*StreamSessionDestroy)(
	struct StreamServer* streamServer,
	struct StreamSession* streamSession);

/*
 * Creates a new stream server (TCP).
 * Returns stream server on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * port - pointer to the valid local address port string.
 * sessionBufferSize - socket session buffer size.
 * receiveBufferSize - socket message receive buffer size.
 * receiveTimeoutTime - socket message receive timeout time (s).
 * receiveFunction - pointer to the valid receive function.
 * createFunction - pointer to the create function or NULL.
 * destroyFunction - pointer to the destroy function or NULL.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	double receiveTimeoutTime,
	StreamSessionReceive receiveFunction,
	StreamSessionCreate createFunction,
	StreamSessionDestroy destroyFunction,
	void* functionArgument,
	struct SslContext* sslContext);

/*
 * Destroys specified stream server.
 * server - pointer to the stream server or NULL.
 */
void destroyStreamServer(
	struct StreamServer* server);

/*
 * Returns stream server receive buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerSessionBufferSize(
	const struct StreamServer* server);

/*
 * Returns stream server receive function.
 * server - pointer to the valid stream server.
 */
StreamSessionReceive getStreamServerReceiveFunction(
	const struct StreamServer* server);

/*
 * Returns stream server create function.
 * server - pointer to the valid stream server.
 */
StreamSessionCreate getStreamServerCreateFunction(
	const struct StreamServer* server);

/*
 * Returns stream server destroy function.
 * server - pointer to the valid stream server.
 */
StreamSessionDestroy getStreamServerDestroyFunction(
	const struct StreamServer* server);

/*
 * Returns stream server receive timeout time (s).
 * server - pointer to the valid stream server.
 */
double getStreamServerReceiveTimeoutTime(
	const struct StreamServer* server);

/*
 * Returns stream server handle.
 * server - pointer to the valid stream server.
 */
void* getStreamServerHandle(
	const struct StreamServer* server);

/*
 * Returns stream server socket.
 * server - pointer to the valid stream server.
 */
struct Socket* getStreamServerSocket(
	const struct StreamServer* server);

/*
 * Returns stream server session socket.
 * session - pointer to the valid stream server session.
 */
struct Socket* getStreamSessionSocket(
	const struct StreamSession* session);

/*
 * Returns stream server session handle.
 * session - pointer to the valid stream server session.
 */
void* getStreamSessionHandle(
	const struct StreamSession* session);

/*
 * Sends datagram to the specified session.
 * Returns true on success.
 *
 * session - pointer to the valid stream session.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool streamSessionSend(
	struct StreamSession* streamSession,
	const void* buffer,
	size_t count);

/*
 * Splits and handles received stream data to the datagrams.
 * Returns true on all handle success
 *
 * receiveBuffer - pointer to the valid receive buffer.
 * byteCount - receive buffer byte count.
 * datagramBuffer - pointer to the valid datagram buffer.
 * datagramByteCount - pointer to the valid datagram buffer byte count.
 * datagramLengthSize - datagram length header size.
 * receiveFunction - pointer to the valid receive handler.
 * functionHandle - pointer to the function handle or NULL.
 */
inline static bool handleStreamDatagram(
	const uint8_t* receiveBuffer,
	size_t byteCount,
	uint8_t* datagramBuffer,
	size_t datagramBufferSize,
	size_t* datagramByteCount,
	size_t datagramLengthSize,
	bool(*receiveFunction)(const uint8_t*, size_t, void*),
	void* functionHandle)
{
	assert(receiveBuffer != NULL);
	assert(byteCount != 0);
	assert(datagramBuffer != NULL);
	assert(datagramBufferSize != 0);
	assert(datagramByteCount != NULL);

	assert(
		datagramLengthSize == sizeof(uint8_t) ||
		datagramLengthSize == sizeof(uint16_t) ||
		datagramLengthSize == sizeof(uint32_t) ||
		datagramLengthSize == sizeof(uint64_t));
	assert(datagramBufferSize >= datagramLengthSize);

	size_t _datagramByteCount =
		*datagramByteCount;

	size_t pointer = 0;

	// Handle received data with buffered data
	if (_datagramByteCount > 0)
	{
		// Datagram buffer has not full size
		if (_datagramByteCount < datagramLengthSize)
		{
			size_t datagramSizePart =
				datagramLengthSize - _datagramByteCount;

			// Received not full datagram size
			if (datagramSizePart > byteCount)
			{
				// Store part of the received datagram size
				memcpy(
					datagramBuffer + _datagramByteCount,
					receiveBuffer,
					byteCount);
				*datagramByteCount += byteCount;
				return true;
			}

			// Copy remaining datagram size part
			memcpy(
				datagramBuffer + _datagramByteCount,
				receiveBuffer,
				datagramSizePart);
			pointer += datagramSizePart;
			_datagramByteCount += datagramSizePart;
		}

		// Decode received datagram size
		uint32_t datagramSize;

		if (datagramLengthSize == sizeof(uint8_t))
			datagramSize = datagramBuffer[0];
		else if (datagramLengthSize == sizeof(uint16_t))
			datagramSize = netToHost16(*(uint16_t*)datagramBuffer);
		else if (datagramLengthSize == sizeof(uint32_t))
			datagramSize = netToHost32(*(uint32_t*)datagramBuffer);
		else if (datagramLengthSize == sizeof(uint64_t))
			datagramSize = netToHost64(*(uint64_t*)datagramBuffer);
		else
			abort();

		// Received datagram is bigger than buffer
		if (datagramSize > datagramBufferSize - datagramLengthSize)
			return false;

		size_t neededPartSize = datagramSize -
			(_datagramByteCount - datagramLengthSize);

		// Received not full datagram
		if (neededPartSize > byteCount - pointer)
		{
			size_t datagramPartSize = byteCount - pointer;

			memcpy(
				datagramBuffer + _datagramByteCount,
				receiveBuffer + pointer,
				datagramPartSize);
			*datagramByteCount = _datagramByteCount + datagramPartSize;
			return true;
		}

		memcpy(
			datagramBuffer + _datagramByteCount,
			receiveBuffer + pointer,
			neededPartSize);

		bool result = receiveFunction(
			datagramBuffer + datagramLengthSize,
			datagramSize,
			functionHandle);

		if (result == false)
			return false;

		*datagramByteCount = 0;
		pointer += neededPartSize;
	}

	// Continue until all received data handled
	while (pointer < byteCount)
	{
		// Received not full datagram size
		if (datagramLengthSize > byteCount - pointer)
		{
			size_t datagramSizePart = byteCount - pointer;

			memcpy(
				datagramBuffer,
				receiveBuffer + pointer,
				datagramSizePart);
			*datagramByteCount += datagramSizePart;
			return true;
		}

		// Decode received datagram size
		uint32_t datagramSize;

		if (datagramLengthSize == sizeof(uint8_t))
			datagramSize = receiveBuffer[pointer];
		else if (datagramLengthSize == sizeof(uint16_t))
			datagramSize = netToHost16(*(uint16_t*)(receiveBuffer + pointer));
		else if (datagramLengthSize == sizeof(uint32_t))
			datagramSize = netToHost32(*(uint32_t*)(receiveBuffer + pointer));
		else if (datagramLengthSize == sizeof(uint64_t))
			datagramSize = netToHost64(*(uint64_t*)(receiveBuffer + pointer));
		else
			abort();

		// Received datagram is bigger than buffer
		if (datagramSize > datagramBufferSize - datagramLengthSize)
			return false;

		// Received not full datagram
		if (datagramSize > (byteCount - pointer) - datagramLengthSize)
		{
			size_t datagramPartSize = byteCount - pointer;

			memcpy(
				datagramBuffer,
				receiveBuffer + pointer,
				datagramPartSize);
			*datagramByteCount += datagramPartSize;
			return true;
		}

		// Handle received datagram data
		bool result = receiveFunction(
			receiveBuffer + pointer + datagramLengthSize,
			datagramSize,
			functionHandle);

		if (result == false)
			return false;

		pointer += datagramLengthSize + datagramSize;
	}

	return true;
}
