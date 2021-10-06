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
    public enum AddressFamily
    {
        IPv4 = 0,
        IPv6 = 1,
        Count = 2,
    }

    public enum SocketType
    {
        Stream = 0,
        Datagram = 1,
        Count = 2,
    }
    
    public enum SocketShutdown
    {
        ReceiveOnly = 0,
        SendOnly = 1,
        ReceiveSend = 2,
        Count = 3,
    }

    public enum SecurityProtocol
    {
        TLS = 0,
        TLS12 = 1,
        Count = 2,
    }
    
    public static class Network
    {
        [DllImport("mpnw")] private static extern bool initializeNetwork();
        [DllImport("mpnw")] private static extern void terminateNetwork();
        [DllImport("mpnw")] private static extern bool isNetworkInitialized();

        public static bool Initialize() => initializeNetwork();
        public static void Terminate() => terminateNetwork();
        public static bool IsInitialized() => isNetworkInitialized();
    }

    public class SocketAddress : ICloneable, IComparable, IComparable<SocketAddress>
    {
        [DllImport("mpnw")] private static extern MpnwResult createSocketAddress(
            string host, string service, ref IntPtr socketAddress);
        [DllImport("mpnw")] private static extern IntPtr createSocketAddressCopy(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern MpnwResult resolveSocketAddress(
            string host, string service, AddressFamily family, SocketType type, ref IntPtr socketAddress);
        [DllImport("mpnw")] private static extern void destroySocketAddress(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern void copySocketAddress(
            IntPtr sourceAddress, IntPtr destinationAddress);
        [DllImport("mpnw")] private static extern int compareSocketAddress(IntPtr a, IntPtr b);
        [DllImport("mpnw")] private static extern AddressFamily getSocketAddressFamily(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern void setSocketAddressFamily(
            IntPtr socketAddress, AddressFamily addressFamily);
        [DllImport("mpnw")] private static extern UIntPtr getSocketAddressFamilyIpSize(AddressFamily addressFamily);
        [DllImport("mpnw")] private static extern UIntPtr getSocketAddressIpSize(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern IntPtr getSocketAddressIp(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern void setSocketAddressIp(
            IntPtr socketAddress, IntPtr ip);
        [DllImport("mpnw")] private static extern ushort getSocketAddressPort(IntPtr socketAddress);
        [DllImport("mpnw")] private static extern void setSocketAddressPort(
            IntPtr socketAddress, ushort port);
        [DllImport("mpnw")] private static extern bool getSocketAddressHost(
            IntPtr socketAddress, IntPtr host, UIntPtr length);
        [DllImport("mpnw")] private static extern bool getSocketAddressService(
            IntPtr socketAddress, IntPtr service, UIntPtr length);
        [DllImport("mpnw")] private static extern bool getSocketAddressHostService(
            IntPtr socketAddress, IntPtr host, UIntPtr hostLength, IntPtr service, UIntPtr serviceLength);

        public const string AnyIPv4 = "0.0.0.0";
        public const string AnyIPv6 = "::";
        
        public const string LoopbackIPv4 = "127.0.0.1";
        public const string LoopbackIPv6 = "::1";
        
        public const string LocalhostHostname = "localhost";
        public const string AnyService = "0";
        
        public const int MaxNumericHostLength = 46;
        public const int MaxNumericServiceLength = 6;

        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        private readonly bool _destroyHandle;

        public AddressFamily Family
        {
            get => getSocketAddressFamily(_handle);
            set
            {
                if (value >= AddressFamily.Count)
                    throw new ArgumentOutOfRangeException(nameof(value));
                
                setSocketAddressFamily(_handle, value);
            }
        }

        public static UIntPtr GetFamilyIpSize(AddressFamily addressFamily)
        {
            if (addressFamily >= AddressFamily.Count)
                throw new ArgumentOutOfRangeException(nameof(addressFamily));
            
            return getSocketAddressFamilyIpSize(addressFamily);
        }

        public UIntPtr IpSize => getSocketAddressIpSize(_handle);

        public IntPtr Ip
        {
            get => getSocketAddressIp(_handle);
            set
            {
                if (value == IntPtr.Zero)
                    throw new ArgumentNullException(nameof(value));
            
                setSocketAddressIp(_handle, value);
            }
        }
        public byte[] IpArray
        {
            get
            {
                var size = (int)getSocketAddressIpSize(_handle);
                var handle = getSocketAddressIp(_handle);

                var array = new byte[size];
                Marshal.Copy(handle, array, 0, size);
                return array;
            }
            set
            {
                var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                var buffer = handle.AddrOfPinnedObject();
                setSocketAddressIp(_handle, buffer);
                handle.Free();
            }
        }

        public ushort Port
        {
            get => getSocketAddressPort(_handle);
            set => setSocketAddressPort(_handle, value);
        }

        public string Host
        {
            get
            {
                var buffer = Marshal.AllocHGlobal(MaxNumericHostLength);

                var result = getSocketAddressHost(_handle, 
                    buffer, (UIntPtr)MaxNumericHostLength);

                if (result == false)
                {
                    Marshal.FreeHGlobal(buffer);
                    return null;
                }

                var host = Marshal.PtrToStringAuto(buffer);
                Marshal.FreeHGlobal(buffer);
                
                return host;
            }
        }
        public string Service
        {
            get
            {
                var buffer = Marshal.AllocHGlobal(MaxNumericHostLength);

                var result = getSocketAddressService(_handle,
                    buffer, (UIntPtr)MaxNumericServiceLength);

                if (result == false)
                {
                    Marshal.FreeHGlobal(buffer);
                    return null;
                }

                var service = Marshal.PtrToStringAuto(buffer);
                Marshal.FreeHGlobal(buffer);
                
                return service;
            }
        }
        public bool GetHostService(out string host, out string service)
        {
            var hostBuffer = Marshal.AllocHGlobal(MaxNumericHostLength);
            var serviceBuffer = Marshal.AllocHGlobal(MaxNumericServiceLength);

            var result = getSocketAddressHostService(_handle, 
                hostBuffer, (UIntPtr)MaxNumericHostLength,
                serviceBuffer, (UIntPtr)MaxNumericServiceLength);

            if (result == false)
            {
                Marshal.FreeHGlobal(serviceBuffer);
                Marshal.FreeHGlobal(hostBuffer);
                
                host = null;
                service = null;
                return false;
            }

            host = Marshal.PtrToStringAuto(hostBuffer);
            service = Marshal.PtrToStringAuto(serviceBuffer);
            
            Marshal.FreeHGlobal(serviceBuffer);
            Marshal.FreeHGlobal(hostBuffer);
            return true;
        }

        public SocketAddress()
        {
            var result = createSocketAddress(AnyIPv4, AnyService, ref _handle);

            if (result != MpnwResult.Success)
                throw new MpnwException(result);

            _destroyHandle = true;
        }
        public SocketAddress(string host, string service)
        {
            if (string.IsNullOrEmpty(host))
                throw new ArgumentNullException(nameof(host));
            if (string.IsNullOrEmpty(service))
                throw new ArgumentNullException(nameof(service));
            
            var result = createSocketAddress(host, service, ref _handle);

            if (result != MpnwResult.Success)
                throw new MpnwException(result);
            
            _destroyHandle = true;
        }
        public SocketAddress(string host, string service, AddressFamily family, SocketType type)
        {
            if (string.IsNullOrEmpty(host))
                throw new ArgumentNullException(nameof(host));
            if (string.IsNullOrEmpty(service))
                throw new ArgumentNullException(nameof(service));
            if (family >= AddressFamily.Count)
                throw new ArgumentOutOfRangeException(nameof(family));
            if (type >= SocketType.Count)
                throw new ArgumentOutOfRangeException(nameof(type));

            var result = resolveSocketAddress(host, service, family, type, ref _handle);

            if (result != MpnwResult.Success)
                throw new MpnwException(result);
            
            _destroyHandle = true;
        }
        private SocketAddress(IntPtr handle, bool destroyHandle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentNullException(nameof(handle));
            
            _handle = handle;
            _destroyHandle = destroyHandle;
        }
        ~SocketAddress()
        {
            if (_destroyHandle)
                destroySocketAddress(_handle);
        }

        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((SocketAddress)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            var result = GetHostService(
                out var host, out var service);

            if (result == false)
                throw new MpnwException("Failed to get host/service");
            
            return host + ":" + service;
        }

        public object Clone() => new SocketAddress(
            createSocketAddressCopy(_handle), true);
        public void Copy(SocketAddress source) => 
            copySocketAddress(source._handle, _handle);

        public int CompareTo(object obj) => 
            compareSocketAddress(_handle, ((SocketAddress)obj)._handle);
        public int CompareTo(SocketAddress other) =>
            compareSocketAddress(_handle, other._handle);
    }

    public class Socket
    { 
        [DllImport("mpnw")] private static extern MpnwResult createSocket(
	        SocketType socketType, AddressFamily addressFamily, IntPtr socketAddress, 
            bool listening, bool blocking, IntPtr sslContext, ref IntPtr socket);
        [DllImport("mpnw")] private static extern void destroySocket(IntPtr socket);
        [DllImport("mpnw")] private static extern SocketType getSocketType(IntPtr socket);
        [DllImport("mpnw")] private static extern bool isSocketListening(IntPtr socket);
        [DllImport("mpnw")] private static extern bool isSocketBlocking(IntPtr socket);
        [DllImport("mpnw")] private static extern bool getSocketLocalAddress(
            IntPtr socket, IntPtr socketAddress);
        [DllImport("mpnw")] private static extern bool getSocketRemoteAddress(
            IntPtr socket, IntPtr socketAddress);
        [DllImport("mpnw")] private static extern IntPtr getSocketSslContext(IntPtr socket);
        [DllImport("mpnw")] private static extern bool isSocketNoDelay(IntPtr socket);
        [DllImport("mpnw")] private static extern void setSocketNoDelay(
            IntPtr socket, bool value);
        [DllImport("mpnw")] private static extern MpnwResult acceptSocket(
            IntPtr socket, ref IntPtr accepted);
        [DllImport("mpnw")] private static extern bool acceptSslSocket(IntPtr socket);
        [DllImport("mpnw")] private static extern bool connectSocket(
            IntPtr socket, IntPtr socketAddress);
        [DllImport("mpnw")] private static extern bool connectSslSocket(IntPtr socket);
        [DllImport("mpnw")] private static extern bool shutdownSocket(
            IntPtr socket, SocketShutdown shutdown);
        [DllImport("mpnw")] private static extern bool socketReceive(
            IntPtr socket, IntPtr receiveBuffer, UIntPtr bufferSize, ref UIntPtr byteCount);
        [DllImport("mpnw")] private static extern bool socketSend(
            IntPtr socket, IntPtr sendBuffer, UIntPtr byteCount);
        [DllImport("mpnw")] private static extern bool socketReceiveFrom(
            IntPtr socket, IntPtr socketAddress, IntPtr receiveBuffer, 
            UIntPtr bufferSize, ref UIntPtr byteCount);
        [DllImport("mpnw")] private static extern  bool socketSendTo(
            IntPtr socket, IntPtr sendBuffer, UIntPtr byteCount, IntPtr socketAddress);

        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        private readonly bool _destroyHandle;

        public SocketType Type => getSocketType(_handle);
        public bool IsListening => isSocketListening(_handle);
        public bool IsBlocking => isSocketBlocking(_handle);

        public SocketAddress LocalAddress
        {
            get
            {
                var socketAddress = new SocketAddress();
                var result = getSocketLocalAddress(_handle, socketAddress.Handle);
                return result ? socketAddress : null;
            }
        }
        public SocketAddress RemoteAddress
        {
            get
            {
                var socketAddress = new SocketAddress();
                var result = getSocketRemoteAddress(_handle, socketAddress.Handle);
                return result ? socketAddress : null;
            }
        }
        
        public SslContext SslContext => 
            new SslContext(getSocketSslContext(_handle), false);

        public bool NoDelay
        {
            get => isSocketNoDelay(_handle);
            set => setSocketNoDelay(_handle, value);
        }

        public Socket(SocketType socketType, AddressFamily addressFamily, 
            SocketAddress socketAddress, bool listening, bool blocking, SslContext sslContext)
        {
            if (socketType >= SocketType.Count)
                throw new ArgumentOutOfRangeException(nameof(socketType));
            if (addressFamily >= AddressFamily.Count)
                throw new ArgumentOutOfRangeException(nameof(addressFamily));

            var sslHandle = sslContext != null ? sslContext.Handle : IntPtr.Zero;

            var result = createSocket(socketType, addressFamily, socketAddress.Handle,
                listening, blocking, sslHandle, ref _handle);

            if (result != MpnwResult.Success)
                throw new MpnwException(result);

            _destroyHandle = true;
        }
        public Socket(IntPtr handle, bool destroyHandle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentNullException(nameof(handle));
            
            _handle = handle;
            _destroyHandle = destroyHandle;
        }
        ~Socket()
        {
            if (_destroyHandle)
                destroySocket(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((Socket)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
        public override string ToString()
        {
            return LocalAddress + " -> " + RemoteAddress;
        }

        public MpnwResult Accept(ref Socket accepted)
        {
            var handle = IntPtr.Zero;
            var result = acceptSocket(_handle, ref handle);

            if (result != MpnwResult.Success)
                return result;

            accepted = new Socket(handle, true);
            return MpnwResult.Success;
        }
        public bool AcceptSSL() => acceptSslSocket(_handle);

        public bool Connect(SocketAddress socketAddress) =>
            connectSocket(_handle, socketAddress.Handle);
        public bool ConnectSSL() => connectSslSocket(_handle);

        public bool Shutdown(SocketShutdown shutdown)
        {
            if (shutdown >= SocketShutdown.Count)
                throw new ArgumentOutOfRangeException(nameof(shutdown));

            return shutdownSocket(_handle, shutdown);
        }

        public bool Receive(IntPtr receiveBuffer, UIntPtr bufferSize, ref UIntPtr byteCount)
        {
            if (receiveBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBuffer));
            if (bufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBuffer));
            
            return socketReceive(_handle, receiveBuffer, bufferSize, ref byteCount);
        }
        public bool Receive(byte[] receiveBuffer, ref UIntPtr byteCount)
        {
            var handle = GCHandle.Alloc(receiveBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            
            var result = socketReceive(_handle, buffer, 
                (UIntPtr)receiveBuffer.Length, ref byteCount);
            
            handle.Free();
            return result;
        }
        
        public bool Send(IntPtr sendBuffer, UIntPtr byteSize)
        {
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));

            return socketSend(_handle, sendBuffer, byteSize);
        }
        public bool Send(byte[] sendBuffer, UIntPtr byteCount)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = socketSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        public bool Send(byte[] sendBuffer, UIntPtr byteCount, int offset)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = socketSend(_handle, buffer, byteCount);
            
            handle.Free();
            return result;
        }
        public bool Send(byte[] sendBuffer) => Send(sendBuffer, (UIntPtr)sendBuffer.Length);
        
        public bool ReceiveFrom(SocketAddress socketAddress, 
            IntPtr receiveBuffer, UIntPtr bufferSize, ref UIntPtr byteCount)
        {
            if (receiveBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBuffer));
            if (bufferSize == UIntPtr.Zero)
                throw new ArgumentNullException(nameof(receiveBuffer));
            
            return socketReceiveFrom(_handle, socketAddress.Handle,
                receiveBuffer, bufferSize, ref byteCount);
        }
        public bool ReceiveFrom(SocketAddress socketAddress,
            byte[] receiveBuffer, ref UIntPtr byteCount)
        {
            var handle = GCHandle.Alloc(receiveBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            
            var result = socketReceiveFrom(_handle, socketAddress.Handle,
                buffer, (UIntPtr)receiveBuffer.Length, ref byteCount);
            
            handle.Free();
            return result;
        }
        
        public bool SendTo(IntPtr sendBuffer, UIntPtr byteSize, SocketAddress socketAddress)
        {
            if (sendBuffer == IntPtr.Zero)
                throw new ArgumentNullException(nameof(sendBuffer));

            return socketSendTo(_handle, sendBuffer, byteSize, socketAddress.Handle);
        }
        public bool SendTo(byte[] sendBuffer, UIntPtr byteCount, SocketAddress socketAddress)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = handle.AddrOfPinnedObject();
            var result = socketSendTo(_handle, buffer, byteCount, socketAddress.Handle);
            
            handle.Free();
            return result;
        }
        public bool Send(byte[] sendBuffer, UIntPtr byteCount, int offset, SocketAddress socketAddress)
        {
            var handle = GCHandle.Alloc(sendBuffer, GCHandleType.Pinned);
            var buffer = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            var result = socketSendTo(_handle, buffer, byteCount, socketAddress.Handle);
            
            handle.Free();
            return result;
        }
        public bool SendTo(byte[] sendBuffer, SocketAddress socketAddress) => 
            SendTo(sendBuffer, (UIntPtr)sendBuffer.Length, socketAddress);
    }

    public class SslContext
    { 
        [DllImport("mpnw")] private static extern MpnwResult createPublicSslContext(
            SecurityProtocol securityProtocol, string certificateFilePath, 
            string certificatesDirectory, ref IntPtr sslContext);
        [DllImport("mpnw")] private static extern MpnwResult createPrivateSslContext(
            SecurityProtocol securityProtocol, string certificateFilePath,  
            string privateKeyFilePath, bool certificateChain, ref IntPtr sslContext);
        [DllImport("mpnw")] private static extern void destroySslContext(IntPtr sslContext);
        [DllImport("mpnw")] private static extern SecurityProtocol getSslContextSecurityProtocol(IntPtr sslContext);

        private readonly IntPtr _handle;
        public IntPtr Handle => _handle;
        
        private readonly bool _destroyHandle;

        public SecurityProtocol SecurityProtocol => getSslContextSecurityProtocol(Handle);
        
        public SslContext(SecurityProtocol securityProtocol, 
            string certificateFilePath, string certificatesDirectory)
        {
            if (securityProtocol >= SecurityProtocol.Count)
                throw new ArgumentOutOfRangeException(nameof(securityProtocol));
            if (string.IsNullOrEmpty(certificateFilePath))
                throw new ArgumentNullException(nameof(certificateFilePath));
            if (string.IsNullOrEmpty(certificatesDirectory))
                throw new ArgumentNullException(nameof(certificatesDirectory));
            
            var result = createPublicSslContext(securityProtocol,
                certificateFilePath, certificatesDirectory, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);

            _destroyHandle = true;
        }
        public SslContext(SecurityProtocol securityProtocol, 
            string certificateFilePath, string privateKeyFilePath, bool certificateChain)
        {
            if (securityProtocol >= SecurityProtocol.Count)
                throw new ArgumentOutOfRangeException(nameof(securityProtocol));
            if (string.IsNullOrEmpty(certificateFilePath))
                throw new ArgumentNullException(nameof(certificateFilePath));
            if (string.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentNullException(nameof(privateKeyFilePath));
            
            var result = createPrivateSslContext(securityProtocol,
                certificateFilePath, privateKeyFilePath, 
                certificateChain, ref _handle);
            
            if (result != MpnwResult.Success)
                throw new MpnwException(result);
            
            _destroyHandle = true;
        }
        public SslContext(IntPtr handle, bool destroyHandle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentNullException(nameof(handle));
            
            _handle = handle;
            _destroyHandle = destroyHandle;
        } 
        ~SslContext()
        {
            if (_destroyHandle)
                destroySslContext(_handle);
        }
        
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;
                
            return _handle == ((SslContext)obj)._handle;
        }
        public override int GetHashCode() => _handle.GetHashCode();
    }
}
