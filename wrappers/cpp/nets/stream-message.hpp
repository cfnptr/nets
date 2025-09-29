// Copyright 2021-2025 Nikita Fediuchin. All rights reserved.
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
 * @brief Network stream message functions.
 * @details See the @ref stream-message.h
 */

#pragma once

extern "C"
{
#include "nets/stream-message.h"
}

namespace nets
{

/**
 * @brief Network stream message container. (TCP)
 * @details See the @ref stream-message.h
 */
struct StreamMessage : public ::StreamMessage
{
	/**
	 * @brief Creates a new empty stream message.
	 */
	StreamMessage() = default;
	/**
	 * @brief Creates a new stream message. (TCP)
	 * @param streamMessage target stream message data
	 */
	StreamMessage(const ::StreamMessage& streamMessage) noexcept
	{
		buffer = streamMessage.buffer;
		size = streamMessage.size;
		offset = streamMessage.offset;
	}
	/**
	 * @brief Creates a new stream message. (TCP)
	 * @details See the @ref createStreamMessage().
	 *
	 * @param[in,out] buffer message data buffer
	 * @param messageSize message size in bytes
	 * @param lengthSize message header size in bytes
	 */
	StreamMessage(uint8_t* buffer, size_t messageSize, uint8_t lengthSize) noexcept
	{
		*this = createStreamMessage(buffer, messageSize, lengthSize);
	}
	/**
	 * @brief Reads data from the stream message and advances offset.
	 * @details See the @ref readStreamMessage().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @param[out] data pointer to the message data
	 * @param count message byte count to read
	 */
	bool read(const uint8_t*& data, size_t count) noexcept { return readStreamMessage(this, &data, count); }
	/**
	 * @brief Returns true if stream message is not empty and complete, otherwise false.
	 * @details See the @ref validateStreamMessage().
	 */
	bool validate() const noexcept { return validateStreamMessage(*this); }
};

} // nets