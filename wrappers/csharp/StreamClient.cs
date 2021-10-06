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
    public abstract class StreamClient
    {
        private delegate void OnStreamClientReceive(
            IntPtr streamClient, IntPtr receiveBuffer, UIntPtr byteCount);
        
        [DllImport("mpnw")] private static extern MpnwResult createStreamClient(
            AddressFamily addressFamily, UIntPtr receiveBufferSize, OnStreamClientReceive onReceive, 
            IntPtr handle, IntPtr sslContext, ref IntPtr streamClient); 
        [DllImport("mpnw")] private static extern void destroyStreamClient(IntPtr streamClient);
        [DllImport("mpnw")] private static extern UIntPtr getStreamClientReceiveBufferSize(IntPtr streamClient);
        [DllImport("mpnw")] private static extern IntPtr getStreamClientSocket(IntPtr streamClient);
        [DllImport("mpnw")] private static extern bool connectStreamClient(
            IntPtr streamClient, IntPtr remoteAddress, double timeoutTime);
        [DllImport("mpnw")] private static extern bool updateStreamClient(IntPtr streamClient);
        [DllImport("mpnw")] private static extern bool streamClientSend(
            IntPtr streamClient, IntPtr sendBuffer, UIntPtr byteCount);

        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        public UIntPtr ReceiveBufferSize => getStreamClientReceiveBufferSize(_handle);
        public Socket Socket => new Socket(getStreamClientSocket(_handle), false);
        
        protected bool Send(IntPtr sendBuffer, UIntPtr byteCount)
        {
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));
            
            return streamClientSend(_handle, sendBuffer, byteCount);
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = streamClientSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount, int offset)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = streamClientSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer) => Send(sendBuffer, (UIntPtr)sendBuffer.Length);

        protected abstract void OnReceive(IntPtr streamClient, IntPtr receiveBuffer, UIntPtr byteCount);
        
        protected StreamClient(AddressFamily addressFamily, UIntPtr receiveBufferSize, SslContext sslContext)
        {
            if (addressFamily >= AddressFamily.Count)
                throw new ArgumentOutOfRangeException(nameof(addressFamily));
            if (receiveBufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBufferSize));

            var sslHandle = sslContext != null ? sslContext.Handle : IntPtr.Zero;

            var result = createStreamClient(addressFamily, receiveBufferSize, OnReceive,
                IntPtr.Zero, sslHandle, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);
        }
        ~StreamClient()
        {
            destroyStreamClient(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((StreamClient)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            return Socket.ToString();
        }

        public bool Connect(SocketAddress remoteAddress, double timeoutTime) =>
            connectStreamClient(_handle, remoteAddress.Handle, timeoutTime);
        public bool Update() => updateStreamClient(_handle);
    }
}
