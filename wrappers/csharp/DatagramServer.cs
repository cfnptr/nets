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
    public abstract class DatagramServer
    {
        private delegate void OnDatagramServerReceive(
            IntPtr datagramServer, IntPtr remoteAddress, 
            IntPtr receiveBuffer, UIntPtr byteCount);
        
        [DllImport("mpnw")] private static extern MpnwResult createDatagramServer(
            AddressFamily addressFamily, string service, UIntPtr receiveBufferSize, 
            OnDatagramServerReceive onReceive, IntPtr handle, ref IntPtr datagramServer);
        [DllImport("mpnw")] private static extern void destroyDatagramServer(IntPtr datagramServer);
        [DllImport("mpnw")] private static extern UIntPtr getDatagramServerReceiveBufferSize(IntPtr datagramServer);
        [DllImport("mpnw")] private static extern IntPtr getDatagramServerSocket(IntPtr datagramServer);
        [DllImport("mpnw")] private static extern bool updateDatagramServer(IntPtr datagramServer);
        [DllImport("mpnw")] private static extern bool datagramServerSend(
            IntPtr datagramServer, IntPtr sendBuffer, UIntPtr byteCount, IntPtr remoteAddress);
        
        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        public UIntPtr ReceiveBufferSize => getDatagramServerReceiveBufferSize(_handle);
        public Socket Socket => new Socket(getDatagramServerSocket(_handle), false);
        
        protected bool Send(IntPtr sendBuffer, UIntPtr byteCount, SocketAddress remoteAddress)
        {
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));
            
            return datagramServerSend(_handle, sendBuffer, byteCount, remoteAddress.Handle);
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount, SocketAddress remoteAddress)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = datagramServerSend(_handle, buffer, byteCount, remoteAddress.Handle);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer, UIntPtr byteCount, int offset, SocketAddress remoteAddress)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = datagramServerSend(_handle, buffer, byteCount, remoteAddress.Handle);
            
            handle.Free();
            return result;
        }
        protected bool Send(byte[] sendBuffer, SocketAddress remoteAddress) => 
            Send(sendBuffer, (UIntPtr)sendBuffer.Length, remoteAddress);
        
        protected abstract void OnReceive(IntPtr datagramServer, 
            IntPtr remoteAddress, IntPtr receiveBuffer, UIntPtr byteCount);
        
        protected DatagramServer(AddressFamily addressFamily, string service, UIntPtr receiveBufferSize)
        {
            if (addressFamily >= AddressFamily.Count)
                throw new ArgumentNullException(nameof(addressFamily));
            if (string.IsNullOrEmpty(service))
                throw new ArgumentNullException(nameof(service));
            if (receiveBufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBufferSize));

            var result = createDatagramServer(addressFamily, service, receiveBufferSize, 
                OnReceive, IntPtr.Zero, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);
        }
        ~DatagramServer()
        {
            destroyDatagramServer(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((DatagramServer)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            return Socket.ToString();
        }
        
        public bool Update() => updateDatagramServer(_handle);
    }
}