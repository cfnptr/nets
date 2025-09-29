// Copyright 2020-2025 Nikita Fediuchin. All rights reserved.
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

/***********************************************************************************************************************
 * @file
 * @brief Common network stream message functions.
 */

#pragma once
#include "nets/defines.h"
#include <string.h>

/**
 * @brief Stream message structure.
 */
typedef struct StreamMessage
{
	const uint8_t* buffer;
	size_t size;
	size_t offset;
} StreamMessage;

/**
 * @brief Creates a new stream message. (TCP)
 *
 * @param[in,out] buffer message data buffer
 * @param messageSize message size in bytes
 * @param lengthSize message header size in bytes
 */
inline static StreamMessage createStreamMessage(uint8_t* buffer, size_t messageSize, uint8_t lengthSize)
{
	assert(buffer != NULL);
	assert(
		(lengthSize == sizeof(uint8_t) && messageSize <= UINT8_MAX) ||
		(lengthSize == sizeof(uint16_t) && messageSize <= UINT16_MAX) ||
		(lengthSize == sizeof(uint32_t) && messageSize <= UINT32_MAX) ||
		(lengthSize == sizeof(uint64_t) && messageSize <= UINT64_MAX));

	StreamMessage streamMessage;
	streamMessage.buffer = buffer;

	if (lengthSize == sizeof(uint8_t))
	{
		buffer[0] = (uint8_t)messageSize;
		streamMessage.size = messageSize + sizeof(uint8_t);
		streamMessage.offset = sizeof(uint8_t);
	}
	else if (lengthSize == sizeof(uint16_t))
	{
		#if NETS_LITTLE_ENDIAN
		*((uint16_t*)buffer) = (uint16_t)messageSize;
		#else
		*((uint16_t*)buffer) = swapBytes16(messageSize);
		#endif
		streamMessage.size = messageSize + sizeof(uint16_t);
		streamMessage.offset = sizeof(uint16_t);
	}
	else if (lengthSize == sizeof(uint32_t))
	{
		#if NETS_LITTLE_ENDIAN
		*((uint32_t*)buffer) = (uint32_t)messageSize;
		#else
		*((uint32_t*)buffer) = swapBytes32(messageSize);
		#endif
		streamMessage.size = messageSize + sizeof(uint32_t);
		streamMessage.offset = sizeof(uint32_t);
	}
	else if (lengthSize == sizeof(uint64_t))
	{
		#if NETS_LITTLE_ENDIAN
		*((uint64_t*)buffer) = (uint64_t)messageSize;
		#else
		*((uint64_t*)buffer) = swapBytes64(messageSize);
		#endif
		streamMessage.size = messageSize + sizeof(uint64_t);
		streamMessage.offset = sizeof(uint64_t);
	}
	else abort();

	return streamMessage;
}
/**
 * @brief Returns true if stream message is not empty and complete, otherwise false.
 * @param streamMessage target stream message to validate
 */
inline static bool validateStreamMessage(StreamMessage streamMessage)
{
	return streamMessage.buffer && streamMessage.size > 0 && streamMessage.size == streamMessage.offset;
}

/**
 * @brief Reads data from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] data pointer to the message data
 * @param count message byte count to read
 */
inline static bool readStreamMessage(StreamMessage* streamMessage, const uint8_t** data, size_t count)
{
	if (streamMessage->offset + count > streamMessage->size)
		return true;

	*data = streamMessage->buffer + streamMessage->offset;
	streamMessage->offset += count;
	return false;
}

/***********************************************************************************************************************
 * @brief Splits received stream data to the messages.
 * @return The receive operation result code.
 *
 * @param[in] receiveBuffer received message buffer
 * @param byteCount message received byte count
 * @param[in,out] messageBuffer intermediate message buffer
 * @param messageBufferSize intermediate message buffer size in bytes (including messageLengthSize)
 * @param[in,out] messageByteCount pointer to the message buffer byte count
 * @param messageLengthSize message length header size in bytes (1, 2, 4 or 8)
 * @param[in] receiveFunction pointer to the receive function
 * @param[in] functionHandle receive function handle or NULL
 */
inline static int handleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, 
	uint8_t* messageBuffer, size_t messageBufferSize, size_t* messageByteCount, 
	uint8_t messageLengthSize, int(*receiveFunction)(StreamMessage, void*), void* functionHandle)
{
	assert(receiveBuffer);
	assert(messageBuffer);
	assert(messageBufferSize > 0);
	assert(messageByteCount);

	assert(messageLengthSize == sizeof(uint8_t) || messageLengthSize == sizeof(uint16_t) ||
		messageLengthSize == sizeof(uint32_t) || messageLengthSize == sizeof(uint64_t));
	assert(messageBufferSize >= messageLengthSize);

	if (byteCount == 0) // Check instead of assert for safety
		return CONNECTION_IS_CLOSED_NETS_RESULT;

	StreamMessage streamMessage;
	streamMessage.offset = 0;

	size_t _messageByteCount = *messageByteCount;
	size_t pointer = 0;
	
	if (_messageByteCount > 0) // Handle received data with buffered data
	{
		if (_messageByteCount < messageLengthSize) // Message buffer has not full size
		{
			size_t messageSizePart = (size_t)messageLengthSize - _messageByteCount;
			if (messageSizePart > byteCount) // Received not full message size
			{
				// Store part of the received message size
				memcpy(messageBuffer + _messageByteCount, receiveBuffer, byteCount * sizeof(uint8_t));
				*messageByteCount += byteCount;
				return SUCCESS_NETS_RESULT;
			}

			// Copy remaining message size part
			memcpy(messageBuffer + _messageByteCount, receiveBuffer, messageSizePart * sizeof(uint8_t));
			pointer += messageSizePart;
			_messageByteCount += messageSizePart;
		}

		uint64_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = messageBuffer[0];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint16_t*)messageBuffer;
			#else
			datagramSize = swapBytes16(*(uint16_t*)datagramBuffer);
			#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint32_t*)messageBuffer;
			#else
			datagramSize = swapBytes32(*(uint32_t*)datagramBuffer);
			#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint64_t*)messageBuffer;
			#else
			datagramSize = swapBytes64(*(uint64_t*)datagramBuffer);
			#endif
		}
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return OUT_OF_MEMORY_NETS_RESULT; // Received message is bigger than buffer

		size_t neededPartSize = messageSize - (_messageByteCount - messageLengthSize);
		if (neededPartSize > byteCount - pointer) 
		{
			size_t messagePartSize = byteCount - pointer;
			memcpy(messageBuffer + _messageByteCount, receiveBuffer + pointer, messagePartSize * sizeof(uint8_t));
			*messageByteCount = _messageByteCount + messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		memcpy(messageBuffer + _messageByteCount, receiveBuffer + pointer, neededPartSize * sizeof(uint8_t));
		streamMessage.buffer = messageBuffer + messageLengthSize;
		streamMessage.size = messageSize;
		
		int result = receiveFunction(streamMessage, functionHandle);
		if (result != SUCCESS_NETS_RESULT)
			return result;

		*messageByteCount = 0;
		pointer += neededPartSize;
	}

	while (pointer < byteCount) // Continue until all received data handled
	{
		if (messageLengthSize > byteCount - pointer)
		{
			size_t messageSizePart = byteCount - pointer;
			memcpy(messageBuffer, receiveBuffer + pointer, messageSizePart * sizeof(uint8_t));
			*messageByteCount += messageSizePart;
			return SUCCESS_NETS_RESULT; // Received not full message size
		}

		uint64_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = receiveBuffer[pointer];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint16_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes16(*(uint16_t*)(receiveBuffer + pointer));
			#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint32_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes32(*(uint32_t*)(receiveBuffer + pointer));
			#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint64_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes64(*(uint64_t*)(receiveBuffer + pointer));
			#endif
		}
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return OUT_OF_MEMORY_NETS_RESULT; // Received message is bigger than buffer

		if (messageSize > (byteCount - pointer) - messageLengthSize)
		{
			size_t messagePartSize = byteCount - pointer;
			memcpy(messageBuffer, receiveBuffer + pointer, messagePartSize * sizeof(uint8_t));
			*messageByteCount += messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		streamMessage.buffer = receiveBuffer + (pointer + messageLengthSize);
		streamMessage.size = messageSize;

		int result = receiveFunction(streamMessage, functionHandle);
		if (result != SUCCESS_NETS_RESULT)
			return result;
		pointer += messageLengthSize + messageSize;
	}

	return SUCCESS_NETS_RESULT;
}

// For library symbols
int sHandleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, uint8_t* messageBuffer, 
	size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize, 
	int(*receiveFunction)(StreamMessage, void*), void* functionHandle);