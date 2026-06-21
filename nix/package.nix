{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "sniproxy-ng";
  version = "0.1.0";
  src = ./..;
  cargoLock.lockFile = ../Cargo.lock;

  meta = with lib; {
    description = "A SNI proxy server supporting QUIC/HTTP3 and HTTP/1.1 with SOCKS5 backend";
    homepage = "https://github.com/anomalyco/sniproxy-ng";
    license = licenses.mit;
    maintainers = [ ];
    mainProgram = "sniproxy-ng";
    platforms = platforms.linux ++ platforms.darwin;
  };
}
