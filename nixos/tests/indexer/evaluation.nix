# Does not evaluate either release package: every enabled module receives stub.
{ pkgs }:
let
  stub = pkgs.runCommand "wazuh-evaluation-stub" { } "mkdir -p $out";
  evaluate = modules: (import "${pkgs.path}/nixos/lib/eval-config.nix" {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      ../../wazuh-indexer
      ../../wazuh-dashboard
      { nixpkgs.pkgs = pkgs; system.stateVersion = "26.05"; boot.isContainer = true; }
    ] ++ modules;
  }).config;
  indexer = {
    services.wazuh-indexer = {
      enable = true;
      package = stub;
      nodeDistinguishedNames = [ "CN=indexer" ];
      tls = { ca = "/secrets/ca"; certificate = "/secrets/cert"; key = "/secrets/key"; };
      admin = { certificate = "/secrets/admin-cert"; key = "/secrets/admin-key"; distinguishedNames = [ "CN=admin" ]; };
      users.admin = { passwordHashFile = "/secrets/hash"; backendRoles = [ "admin" ]; };
    };
  };
  dashboard = {
    services.wazuh-dashboard = {
      enable = true;
      package = stub;
      tls = { certificate = "/secrets/cert"; key = "/secrets/key"; };
      indexer = { hosts = [ "https://indexer:9200" ]; ca = "/secrets/ca"; usernameFile = "/secrets/user"; passwordFile = "/secrets/password"; };
      managers = [ { url = "https://server"; usernameFile = "/secrets/api-user"; passwordFile = "/secrets/api-password"; } ];
    };
  };
  disabled = evaluate [ ];
  indexerOnly = evaluate [ indexer ];
  dashboardOnly = evaluate [ dashboard ];
  together = evaluate [ indexer dashboard ];
  valid = cfg: builtins.all (a: a.assertion) cfg.assertions;
  checks = [
    (!(disabled.systemd.services ? wazuh-indexer))
    (!(disabled.systemd.services ? wazuh-dashboard))
    (valid indexerOnly)
    (valid dashboardOnly)
    (valid together)
    (!(indexerOnly.systemd.services ? wazuh-dashboard))
    (!(dashboardOnly.systemd.services ? wazuh-indexer))
    (together.systemd.services.wazuh-indexer.serviceConfig.User == "wazuh-indexer")
    (together.systemd.services.wazuh-dashboard.serviceConfig.User == "wazuh-dashboard")
    (builtins.elem "key:/secrets/key" together.systemd.services.wazuh-indexer.serviceConfig.LoadCredential)
    (!(builtins.elem "key:/secrets/admin-key" together.systemd.services.wazuh-indexer.serviceConfig.LoadCredential))
    (builtins.elem "key:/secrets/admin-key" together.systemd.services.wazuh-indexer-security.serviceConfig.LoadCredential)
    (together.networking.firewall.allowedTCPPorts == [ ])
    (!(valid (evaluate [ indexer { services.wazuh-indexer.users = pkgs.lib.mkForce { }; } ])))
    (!(valid (evaluate [ dashboard { services.wazuh-dashboard.indexer.hosts = [ "http://indexer:9200" ]; } ])))
  ];
in assert builtins.all (x: x) checks;
  pkgs.runCommand "wazuh-component-evaluation" { } "touch $out"
