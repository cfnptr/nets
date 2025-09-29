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

#include "nets/stream-message.h"

int sHandleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, uint8_t* messageBuffer, 
	size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize, 
	int(*receiveFunction)(StreamMessage, void*), void* functionHandle)
{
	return handleStreamMessage(receiveBuffer, byteCount, messageBuffer, messageBufferSize, 
		messageByteCount, messageLengthSize, receiveFunction, functionHandle);
}