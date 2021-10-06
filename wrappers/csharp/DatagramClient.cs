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
using System.Runtime.InteropServices;

namespace Mpnw
{
    public abstract class DatagramClient
    {
        private delegate void OnDatagramClientReceive(
            IntPtr datagramClient, IntPtr receiveBuffer, UIntPtr byteCount);
        
        [DllImport("mpnw")] private static extern MpnwResult createDatagramClient(
            IntPtr remoteAddress, UIntPtr receiveBufferSize, OnDatagramClientReceive onReceive, 
            IntPtr handle, ref IntPtr datagramClient);
        [DllImport("mpnw")] private static extern void destroyDatagramClient(IntPtr datagramClient);
        [DllImport("mpnw")] private static extern UIntPtr getDatagramClientReceiveBufferSize(IntPtr datagramClient);
        [DllImport("mpnw")] private static extern IntPtr getDatagramClientSocket(IntPtr datagramClient);
        [DllImport("mpnw")] private static extern bool updateDatagramClient(IntPtr datagramClient);
        [DllImport("mpnw")] private static extern bool datagramClientSend(
            IntPtr datagramClient, IntPtr sendBuffer, UIntPtr byteCount);
        
        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        public UIntPtr ReceiveBufferSize => getDatagramClientReceiveBufferSize(_handle);
        public Socket Socket => new Socket(getDatagramClientSocket(_handle), false);
        
        protected bool Send(IntPtr sendBuffer, UIntPtr byteCount)
        {
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));
            
            return datagramClientSend(_handle, sendBuffer, byteCount);
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = datagramClientSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount, int offset)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = datagramClientSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer) => Send(sendBuffer, (UIntPtr)sendBuffer.Length);
        
        protected abstract void OnReceive(IntPtr datagramClient, IntPtr receiveBuffer, UIntPtr byteCount);
        
        protected DatagramClient(SocketAddress remoteAddress, UIntPtr receiveBufferSize)
        {
            if (receiveBufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBufferSize));

            var result = createDatagramClient(remoteAddress.Handle, receiveBufferSize, 
                OnReceive, IntPtr.Zero, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);
        }
        ~DatagramClient()
        {
            destroyDatagramClient(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((DatagramClient)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            return Socket.ToString();
        }
        
        public bool Update() => updateDatagramClient(_handle);
    }
}