{ config, lib, pkgs, ... }:

let
  cfg = config.services.sniproxy-ng;
  tomlFormat = pkgs.formats.toml { };
  defaultPackage = pkgs.callPackage ./package.nix { };

  configSource =
    if cfg.configFile != null
    then cfg.configFile
    else "${config.environment.etc."sniproxy-ng/config.toml".source}";
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
      type = lib.types.nullOr tomlFormat.type;
      default = null;
      description = ''
        Configuration attribute set written to config.toml.
        Either this or configFile must be set, not both.
        WARNING: secrets (e.g. socks5.password) will be stored in the Nix store.
        Use configFile for secret-managed configurations.
      '';
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

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path to an existing runtime config.toml file.
        Either this or settings must be set, not both.
        Prefer this over settings when secrets are involved, because this path is
        used at runtime and is not copied into the Nix store.
      '';
      example = "/run/secrets/sniproxy-ng/config.toml";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.settings != null || cfg.configFile != null;
        message = "One of services.sniproxy-ng.settings or services.sniproxy-ng.configFile must be set.";
      }
      {
        assertion = !(cfg.settings != null && cfg.configFile != null);
        message = "Only one of services.sniproxy-ng.settings or services.sniproxy-ng.configFile should be set, not both.";
      }
    ];

    environment.etc."sniproxy-ng/config.toml" = lib.mkIf (cfg.settings != null) {
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
        ExecStartPre = "${lib.getBin pkgs.coreutils}/bin/ln -sf ${configSource} /var/lib/sniproxy-ng/config.toml";

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
