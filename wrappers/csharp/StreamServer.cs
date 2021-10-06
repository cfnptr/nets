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
    public abstract class StreamServer
    {
        private delegate bool OnStreamSessionCreate(
            IntPtr streamServer, IntPtr socket, ref IntPtr handle);
        private delegate void OnStreamSessionDestroy(
            IntPtr streamServer, IntPtr streamSession);
        private delegate bool OnStreamSessionUpdate(
            IntPtr streamServer, IntPtr streamSession);
        private delegate bool OnStreamSessionReceive(
            IntPtr streamServer, IntPtr streamSession, 
            IntPtr receiveBuffer, UIntPtr byteCount);
        
        [DllImport("mpnw")] private static extern MpnwResult createStreamServer(
            AddressFamily addressFamily, string service, UIntPtr sessionBufferSize, UIntPtr receiveBufferSize, 
            OnStreamSessionCreate onCreate, OnStreamSessionDestroy onDestroy, 
            OnStreamSessionUpdate onUpdate, OnStreamSessionReceive onReceive, 
            IntPtr handle, IntPtr sslContext, ref IntPtr streamServer);
        [DllImport("mpnw")] private static extern void destroyStreamServer(IntPtr streamServer);
        [DllImport("mpnw")] private static extern UIntPtr getStreamServerSessionBufferSize(IntPtr streamServer);
        [DllImport("mpnw")] private static extern UIntPtr getStreamServerReceiveBufferSize(IntPtr streamServer);
        [DllImport("mpnw")] private static extern IntPtr getStreamServerSocket(IntPtr streamServer);
        [DllImport("mpnw")] private static extern IntPtr getStreamSessionSocket(IntPtr streamSession);
        [DllImport("mpnw")] private static extern bool updateStreamServer(IntPtr streamServer);
        [DllImport("mpnw")] private static extern bool streamSessionSend(
            IntPtr streamSession, IntPtr sendBuffer, UIntPtr byteCount);
        
        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        public UIntPtr SessionBufferSize => getStreamServerSessionBufferSize(_handle);
        public UIntPtr ReceiveBufferSize => getStreamServerReceiveBufferSize(_handle);
        public Socket Socket => new Socket(getStreamServerSocket(_handle), false);

        protected Socket GetSessionSocket(IntPtr streamSession)
        {
            if (streamSession == IntPtr.Zero)
                throw new ArgumentNullException(nameof(streamSession));

            return new Socket(getStreamSessionSocket(_handle), false);
        }
        
        protected bool Send(IntPtr streamSession, IntPtr sendBuffer, UIntPtr byteCount)
        {
            if (streamSession == IntPtr.Zero)
                throw new ArgumentNullException(nameof(streamSession));
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));
            
            return streamSessionSend(streamSession, sendBuffer, byteCount);
        }
        protected bool Send(IntPtr streamSession, byte[] sendBuffer, UIntPtr byteCount)
        {
            if (streamSession == IntPtr.Zero)
                throw new ArgumentNullException(nameof(streamSession));
            
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = streamSessionSend(streamSession, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(IntPtr streamSession, byte[] sendBuffer, UIntPtr byteCount, int offset)
        {
            if (streamSession == IntPtr.Zero)
                throw new ArgumentNullException(nameof(streamSession));
            
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = streamSessionSend(streamSession, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        protected bool Send(IntPtr streamSession, byte[] sendBuffer) => 
            Send(streamSession, sendBuffer, (UIntPtr)sendBuffer.Length);

        protected abstract bool OnSessionCreate(IntPtr streamServer, IntPtr socket, ref IntPtr handle);
        protected abstract void OnSessionDestroy(IntPtr streamServer, IntPtr streamSession);
        protected abstract bool OnSessionUpdate(IntPtr streamServer, IntPtr streamSession);
        
        protected abstract bool OnSessionReceive(
            IntPtr streamServer, IntPtr streamSession, 
            IntPtr receiveBuffer, UIntPtr byteCount);

        protected StreamServer(AddressFamily addressFamily, string service, 
            UIntPtr sessionBufferSize, UIntPtr receiveBufferSize, SslContext sslContext)
        {
            if (addressFamily >= AddressFamily.Count)
                throw new ArgumentOutOfRangeException(nameof(addressFamily));
            if (string.IsNullOrEmpty(service))
                throw new ArgumentNullException(nameof(service));
            if (sessionBufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(sessionBufferSize));
            if (receiveBufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBufferSize));
            
            var sslHandle = sslContext != null ? sslContext.Handle : IntPtr.Zero;

            var result = createStreamServer(
                addressFamily, service, sessionBufferSize, receiveBufferSize, 
                OnSessionCreate, OnSessionDestroy, OnSessionUpdate, OnSessionReceive, 
                IntPtr.Zero, sslHandle, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);
        }
        ~StreamServer()
        {
            destroyStreamServer(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((StreamServer)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            return Socket.ToString();
        }
        
        public bool Update() => updateStreamServer(_handle);
    }
}
