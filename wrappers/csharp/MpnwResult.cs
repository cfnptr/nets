// Copyright 2020-2021 Nikita Fediuchin. All rights reserved.
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

using System;

namespace Mpnw
{
    public enum MpnwResult
    {
        Success = 0,
        NetworkIsNotInitialized = 1,
        FailedToAllocate = 2,
        FailedToCreateSocket = 3,
        FailedToBindSocket = 4,
        FailedToListenSocket = 5,
        FailedToAcceptSocket = 6,
        FailedToConnectSocket = 7,
        FailedToSetSocketFlag = 8,
        FailedToGetAddressInfo = 9,
        FailedToCreateSSL = 10,
        FailedToLoadCertificate = 11,
        Count = 12,
    }

    public class MpnwException : Exception
    {
        public MpnwException(MpnwResult result) :
            base(result.ToString()) { }
        public MpnwException(string message) :
            base(message) { }
    }
}
