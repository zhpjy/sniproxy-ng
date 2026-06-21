{ config, lib, pkgs, ... }:

let
  cfg = config.services.sniproxy-ng;
  tomlFormat = pkgs.formats.toml { };
  defaultPackage = pkgs.callPackage ./package.nix { };
in
{
  options.services.sniproxy-ng = {
    enable = lib.mkEnableOption "sniproxy-ng SNI proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "sniproxy-ng";
      description = "sniproxy-ng package to use.";
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      description = "Configuration attribute set written to config.toml.";
      example = {
        server = {
          listen_https_addr = "0.0.0.0:443";
          listen_http_addr = "0.0.0.0:80";
        };
        socks5 = {
          addr = "127.0.0.1:1080";
          timeout = 30;
          max_connections = 100;
        };
        rules.allow = [ ];
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."sniproxy-ng/config.toml" = {
      source = tomlFormat.generate "config.toml" cfg.settings;
    };

    systemd.services.sniproxy-ng = {
      description = "sniproxy-ng - SNI Proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/sniproxy-ng";
        WorkingDirectory = "/var/lib/sniproxy-ng";
        ExecStartPre = "${lib.getBin pkgs.coreutils}/bin/ln -sf /etc/sniproxy-ng/config.toml /var/lib/sniproxy-ng/config.toml";

        DynamicUser = true;
        AmbientCapabilities = "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = "@system-service";

        LimitNOFILE = 65536;
        StateDirectory = "sniproxy-ng";

        StandardOutput = "journal";
        StandardError = "journal";
      };
    };
  };
}
