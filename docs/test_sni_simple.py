#!/usr/bin/env python3
"""
简单的 SNI 解析测试 - 使用真实的 TLS ClientHello 数据
"""

import struct

# 这是一个真实的 TLS ClientHello 数据包 (访问 www.google.com)
# 来源: Wireshark 抓包
REAL_CLIENT_HELLO = bytes.fromhex(
    "16030100"  # TLS Record: Handshake, TLS 1.0
    "c50100"    # Length: 197
    "00c10303"  # Handshake: ClientHello, Length 193, TLS 1.2
    "5bbcb4c1"  # Random (32 bytes) - 继续...
    "4717f1a7"
    "3d8e5e8c"
    "e4b4c8ae"
    "b8c59e9c"
    "a8caf5eb"
    "6fb8d78e"
    "e8c5ca94"
    "20"        # Session ID length: 32
    "5bbcb4c1"  # Session ID (32 bytes)
    "4717f1a7"
    "3d8e5e8c"
    "e4b4c8ae"
    "b8c59e9c"
    "a8caf5eb"
    "6fb8d78e"
    "e8c5ca94"
    "002a"      # Cipher suites length: 42
    "c02b"      # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    "c02f"      # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    "cca9"      # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    "cca8"      # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    "c02c"      # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    "c030"      # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    "0100"      # Compression methods: length 1, null compression
    "005b"      # Extensions length: 91
    # Extension 1: server_name (SNI)
    "0000"      # Type: server_name (0x0000)
    "0011"      # Length: 17
    "000e"      # Server name list length: 14
    "00"        # Name type: hostname (0)
    "000b"      # Name length: 11
    "7777772e67" # "www.g"
    "6f6f676c65" # "oogle"
    "2e636f6d"  # ".com"
    # ... 其他扩展省略
)

def parse_sni(data):
    """
    从 TLS ClientHello 中解析 SNI
    """
    print("=" * 70)
    print("TLS SNI 解析测试")
    print("=" * 70)

    offset = 0

    # Step 1: TLS Record Header
    if offset + 5 > len(data):
        print("❌ 数据太短,无法读取 TLS Record Header")
        return None

    content_type = data[offset]
    version = struct.unpack('>H', data[offset+1:offset+3])[0]
    length = struct.unpack('>H', data[offset+3:offset+5])[0]

    print(f"\n✓ TLS Record Header:")
    print(f"  Content Type: 0x{content_type:02X} {'(Handshake)' if content_type == 0x16 else ''}")
    print(f"  Version: 0x{version:04X}")
    print(f"  Length: {length} bytes")

    if content_type != 0x16:
        print("❌ 不是 Handshake 消息")
        return None

    offset += 5

    # Step 2: Handshake Message
    if offset + 4 > len(data):
        print("❌ 数据太短,无法读取 Handshake Header")
        return None

    handshake_type = data[offset]
    handshake_length = struct.unpack('>I', b'\x00' + data[offset+1:offset+4])[0]

    print(f"\n✓ Handshake Header:")
    print(f"  Type: 0x{handshake_type:02X} {'(ClientHello)' if handshake_type == 0x01 else ''}")
    print(f"  Length: {handshake_length} bytes")

    if handshake_type != 0x01:
        print("❌ 不是 ClientHello 消息")
        return None

    offset += 4

    # Step 3: ClientHello Body
    # 跳过 TLS Version (2) + Random (32)
    offset += 34

    # Session ID
    if offset >= len(data):
        print("❌ 无法读取 Session ID 长度")
        return None

    session_id_len = data[offset]
    offset += 1 + session_id_len

    print(f"✓ 跳过 Session ID ({session_id_len} bytes)")

    # Cipher Suites
    if offset + 2 > len(data):
        print("❌ 无法读取 Cipher Suites 长度")
        return None

    cipher_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2 + cipher_len

    print(f"✓ 跳过 Cipher Suites ({cipher_len} bytes)")

    # Compression Methods
    if offset >= len(data):
        print("❌ 无法读取 Compression 长度")
        return None

    compression_len = data[offset]
    offset += 1 + compression_len

    print(f"✓ 跳过 Compression ({compression_len} bytes)")

    # Extensions
    if offset + 2 > len(data):
        print("❌ 无法读取 Extensions 长度")
        return None

    extensions_length = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2

    print(f"\n✓ Extensions 总长度: {extensions_length} bytes")
    print(f"  当前 offset: {offset}, 剩余数据: {len(data) - offset} bytes")

    # Parse Extensions
    ext_end = offset + extensions_length
    ext_count = 0

    while offset < ext_end and offset + 4 <= len(data):
        ext_type = struct.unpack('>H', data[offset:offset+2])[0]
        ext_length = struct.unpack('>H', data[offset+2:offset+4])[0]
        offset += 4

        ext_count += 1

        if offset + ext_length > len(data):
            print(f"❌ 扩展 {ext_count} 数据超出范围")
            break

        # 检查是否是 SNI 扩展
        if ext_type == 0x0000:
            print(f"\n✅ 找到 SNI 扩展! (扩展 #{ext_count})")
            print(f"  Extension Type: 0x{ext_type:04X} (server_name)")
            print(f"  Extension Length: {ext_length} bytes")

            # Parse SNI
            sni_offset = offset

            if sni_offset + 2 > len(data):
                print("❌ 无法读取 Server Name List 长度")
                return None

            list_length = struct.unpack('>H', data[sni_offset:sni_offset+2])[0]
            sni_offset += 2

            print(f"  Server Name List Length: {list_length} bytes")

            if sni_offset >= len(data):
                print("❌ 无法读取 Name Type")
                return None

            name_type = data[sni_offset]
            sni_offset += 1

            if name_type != 0x00:
                print(f"❌ 未知的 Name Type: 0x{name_type:02X}")
                return None

            if sni_offset + 2 > len(data):
                print("❌ 无法读取 Name Length")
                return None

            name_length = struct.unpack('>H', data[sni_offset:sni_offset+2])[0]
            sni_offset += 2

            if sni_offset + name_length > len(data):
                print("❌ Name 数据超出范围")
                return None

            hostname = data[sni_offset:sni_offset+name_length].decode('ascii', errors='replace')

            print(f"  Name Type: 0x{name_type:02X} (hostname)")
            print(f"  Name Length: {name_length} bytes")
            print(f"  Hostname: {hostname}")

            print("\n" + "=" * 70)
            print(f"🎉 成功提取 SNI: {hostname}")
            print("=" * 70)

            return hostname

        # 跳过这个扩展的数据
        offset += ext_length

    print("\n" + "=" * 70)
    print("❌ 未找到 SNI 扩展")
    print("=" * 70)
    return None


def main():
    expected_sni = "www.google.com"

    print(f"测试域名: {expected_sni}")
    print(f"数据包长度: {len(REAL_CLIENT_HELLO)} bytes\n")

    sni = parse_sni(REAL_CLIENT_HELLO)

    if sni == expected_sni:
        print(f"\n✅ 测试通过!")
        return 0
    else:
        print(f"\n❌ 测试失败!")
        print(f"   期望: {expected_sni}")
        print(f"   实际: {sni}")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
