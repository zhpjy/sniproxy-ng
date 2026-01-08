#!/bin/bash
# QUIC SNI 提取测试脚本
# 用于生成真实的 QUIC Initial packets

set -e

echo "================================"
echo "QUIC SNI 提取测试工具"
echo "================================"
echo ""

# 检查 openssl 是否支持 QUIC
if ! openssl s_client -help 2>&1 | grep -q -- -quic; then
    echo "⚠️  Warning: openssl 可能不支持 -quic 参数"
    echo "尝试使用 -tls1_3 代替"
fi

echo ""
echo "方法 1: 使用 openssl 生成 QUIC ClientHello"
echo "-----------------------------------------------"
echo ""
echo "命令:"
echo "  echo 'GET /' | openssl s_client -connect www.google.com:443 -quic -tls1_3 2>&1 | head -50"
echo ""
echo "这会发送一个 QUIC Initial packet，但需要网络连接"
echo ""

echo "方法 2: 使用预定义的测试数据"
echo "--------------------------------"
echo ""
echo "从 Wireshark 或其他工具抓取的 QUIC Initial packet 可以用于测试"
echo ""

echo "方法 3: 手动构造测试 packet"
echo "--------------------------------"
echo ""
echo "创建一个简单的测试脚本来验证功能"
echo ""

# 创建一个简单的测试程序
cat > /tmp/test_quic_sni.rs <<'EOF'
use std::net::UdpSocket;

fn main() {
    println!("QUIC SNI 提取测试程序");
    println!("=====================");
    println!();

    // 绑定 UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");
    println!("✅ UDP socket 绑定成功");
    println!();

    // 发送一个简单的 UDP packet 到 google.com:443
    // 这不会是一个有效的 QUIC packet，但可以测试 UDP 通信
    let buf = [0u8; 8];
    println!("发送测试 packet 到 www.google.com:443...");

    match socket.send_to(&buf, "www.google.com:443") {
        Ok(len) => println!("✅ 发送 {} 字节", len),
        Err(e) => println!("❌ 发送失败: {}", e),
    }

    println!();
    println!("提示: 要测试真实的 QUIC SNI 提取，需要:");
    println!("1. 使用 Wireshark 抓取真实的 QUIC Initial packets");
    println!("2. 或者让客户端连接到我们的 UDP 服务器");
    println!("3. 然后使用 extract_sni_from_quic_initial() 提取 SNI");
}
EOF

echo "✅ 测试程序已创建: /tmp/test_quic_sni.rs"
echo ""
echo "运行测试:"
echo "  rustc /tmp/test_quic_sni.rs -o /tmp/test_quic_sni"
echo "  /tmp/test_quic_sni"
echo ""

echo "方法 4: 启动 sniproxy-ng UDP 服务器"
echo "--------------------------------------"
echo ""
echo "命令:"
echo "  cargo run --release"
echo ""
echo "然后使用浏览器或其他 QUIC 客户端连接到监听端口"
echo ""

# 显示当前 git commit
echo "当前代码版本:"
git log -1 --oneline 2>/dev/null || echo "  (git 不可用)"
echo ""

echo "测试文件已创建:"
echo "  - tests/quic_integration_test.rs (需要修复编译)"
echo "  - /tmp/test_quic_sni.rs (简单的 UDP 测试)"
echo ""
