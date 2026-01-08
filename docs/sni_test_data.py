#!/usr/bin/env python3
"""
生成 TLS ClientHello 测试数据

用法:
    python3 sni_test_data.py
"""

import socket
import struct

def build_tls_client_hello(sni_hostname="www.example.com"):
    """
    构造一个包含 SNI 的 TLS ClientHello 消息
    """
    # TLS Record Layer Header
    content_type = 0x16  # Handshake
    version = 0x0303     # TLS 1.2

    # Handshake Message
    handshake_type = 0x01  # ClientHello
    tls_version = 0x0303   # TLS 1.2
    random = b'\x00' * 32  # 简化的随机数
    session_id = b'\x00'   # 空 session ID

    # Cipher Suites (一些常见的)
    cipher_suites = bytes([
        0x00, 0x2C,  # Length
        # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC0, 0x2F,
        # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC0, 0x35,
    ])

    # Compression Methods
    compression_methods = b'\x01\x00'  # 只支持 null compression

    # Extensions
    extensions = build_sni_extension(sni_hostname)

    # 组装 ClientHello
    client_hello = (
        bytes([handshake_type]) +
        struct.pack('>I', 0)[1:] +  # Length 占位符 (3 bytes)
        struct.pack('>H', tls_version) +
        random +
        bytes([len(session_id)]) + session_id +
        cipher_suites +
        compression_methods +
        struct.pack('>H', len(extensions)) +
        extensions
    )

    # 更新 Handshake 长度
    handshake_length = len(client_hello) - 4
    client_hello = (
        client_hello[:1] +
        struct.pack('>I', handshake_length)[1:] +
        client_hello[4:]
    )

    # 组装 TLS Record
    record = (
        bytes([content_type]) +
        struct.pack('>H', version) +
        struct.pack('>H', len(client_hello)) +
        client_hello
    )

    return record


def build_sni_extension(hostname):
    """
    构建 SNI 扩展
    """
    # SNI extension type
    ext_type = struct.pack('>H', 0x0000)

    # 将 hostname 转换为字节
    hostname_bytes = hostname.encode('ascii')

    # Server Name List
    server_name_list = (
        b'\x00' +  # Name Type: hostname
        struct.pack('>H', len(hostname_bytes)) +
        hostname_bytes
    )

    # Server Name List Length
    list_length = struct.pack('>H', len(server_name_list))

    # Extension Data
    ext_data = list_length + server_name_list

    # Extension Length
    ext_length = struct.pack('>H', len(ext_data))

    # 完整的 Extension
    extension = ext_type + ext_length + ext_data

    return extension


def print_hex_dump(data, label="Data"):
    """
    打印十六进制转储
    """
    print(f"\n{label}:")
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f'{i:04X}: {hex_part:<48} {ascii_part}')


def test_parse_sni(data):
    """
    测试解析 SNI (简化版)
    """
    print("\n" + "="*60)
    print("解析 TLS ClientHello:")
    print("="*60)

    offset = 0

    # TLS Record Header
    content_type = data[offset]
    version = struct.unpack('>H', data[offset+1:offset+3])[0]
    length = struct.unpack('>H', data[offset+3:offset+5])[0]

    print(f"\n✓ TLS Record Header:")
    print(f"  Content Type: 0x{content_type:02X} {'(Handshake)' if content_type == 0x16 else ''}")
    print(f"  Version: 0x{version:04X}")
    print(f"  Length: {length} bytes")

    offset += 5

    # 只使用 payload 部分
    payload = data[offset:offset+length]
    print(f"\n✓ 使用 payload 进行解析 (长度: {len(payload)} 字节)")

    # 重新从 payload 开始
    offset = 0

    # Handshake Header
    handshake_type = payload[offset]
    handshake_length = struct.unpack('>I', b'\x00' + payload[offset+1:offset+4])[0]

    print(f"\n✓ Handshake Header:")
    print(f"  Type: 0x{handshake_type:02X} {'(ClientHello)' if handshake_type == 0x01 else ''}")
    print(f"  Length: {handshake_length} bytes")

    offset += 4

    # ClientHello 固定字段
    offset += 2  # TLS Version
    offset += 32  # Random

    print(f"\n✓ ClientHello 固定字段后 offset = {offset}, 总长度 = {len(payload)}")

    # Session ID
    if offset >= len(payload):
        print(f"❌ 错误: offset {offset} 超出范围")
        return None

    session_id_len = payload[offset]
    offset += 1 + session_id_len

    print(f"✓ Session ID 后 offset = {offset}")

    # Cipher Suites
    if offset + 2 > len(payload):
        print(f"❌ 错误: offset {offset} 超出范围 (需要2字节)")
        return None

    cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
    offset += 2 + cipher_len

    print(f"✓ Cipher Suites 后 offset = {offset}")

    # Compression
    if offset >= len(payload):
        print(f"❌ 错误: offset {offset} 超出范围")
        return None

    compression_len = payload[offset]
    offset += 1 + compression_len

    print(f"✓ Compression 后 offset = {offset}")

    # Extensions
    extensions_length = struct.unpack('>H', payload[offset:offset+2])[0]
    offset += 2

    print(f"\n✓ Extensions (总长度: {extensions_length} bytes):")

    # 遍历扩展
    ext_end = offset + extensions_length
    found_sni = None

    while offset < ext_end:
        ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
        ext_length = struct.unpack('>H', payload[offset+2:offset+4])[0]
        ext_data_start = offset + 4

        if ext_type == 0x0000:
            print(f"\n✓ 找到 SNI 扩展!")
            print(f"  Type: 0x{ext_type:04X} (SNI)")
            print(f"  Length: {ext_length} bytes")

            # 解析 SNI
            sni_offset = ext_data_start
            list_length = struct.unpack('>H', payload[sni_offset:sni_offset+2])[0]
            sni_offset += 2

            name_type = payload[sni_offset]
            sni_offset += 1

            name_length = struct.unpack('>H', payload[sni_offset:sni_offset+2])[0]
            sni_offset += 2

            hostname = payload[sni_offset:sni_offset+name_length].decode('ascii')
            found_sni = hostname

            print(f"  Hostname: {hostname}")
            break

        offset += 4 + ext_length

    print("\n" + "="*60)
    if found_sni:
        print(f"✅ 成功提取 SNI: {found_sni}")
    else:
        print("❌ 未找到 SNI")
    print("="*60)

    return found_sni


def main():
    """
    主函数
    """
    import sys

    # 默认测试域名
    hostname = sys.argv[1] if len(sys.argv) > 1 else "www.google.com"

    print("="*60)
    print(f"TLS SNI 提取测试")
    print(f"目标域名: {hostname}")
    print("="*60)

    # 生成测试数据
    data = build_tls_client_hello(hostname)

    # 打印十六进制
    print_hex_dump(data, "完整的 TLS ClientHello 数据包")

    # 解析 SNI
    sni = test_parse_sni(data)

    # 验证
    if sni == hostname:
        print(f"\n✅ 测试通过! 成功提取 SNI: {sni}")
        return 0
    else:
        print(f"\n❌ 测试失败! 期望: {hostname}, 实际: {sni}")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
