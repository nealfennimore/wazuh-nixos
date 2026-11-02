# Resolve references without reading secret contents during evaluation.
{ cfg, lib }:
let
  validName = name: builtins.isString name && builtins.match "[A-Za-z0-9_-]+" name != null;
  token = name: "@WAZUH_SECRET_settings-${name}@";
  credentialPath = name: "/var/ossec/etc/credentials/${name}";
  fail = message: throw "services.wazuh-server: ${message}";
  resolveAt =
    inAttribute: value:
    if builtins.isList value then
      map (resolveAt inAttribute) value
    else if !builtins.isAttrs value then
      value
    else if value ? _secret then
      if builtins.attrNames value != [ "_secret" ] || !validName value._secret then
        fail "a secret reference must be exactly { _secret = \"name\"; } with an identifier name"
      else if inAttribute then
        fail "secret references are allowed in element text, not XML attributes"
      else if !(builtins.hasAttr value._secret cfg.secretFiles) then
        fail "undefined secretFiles.${value._secret}"
      else
        token value._secret
    else if value ? _credential then
      if builtins.attrNames value != [ "_credential" ] || !validName value._credential then
        fail "a credential reference must be exactly { _credential = \"name\"; } with an identifier name"
      else if !(builtins.hasAttr value._credential cfg.credentialFiles) then
        fail "undefined credentialFiles.${value._credential}"
      else
        credentialPath value._credential
    else
      lib.mapAttrs (name: child: resolveAt (inAttribute || name == "_attributes") child) value;
  references =
    value:
    if builtins.isList value then
      lib.concatMap references value
    else if !builtins.isAttrs value then
      [ ]
    else if value ? _secret then
      [ value._secret ]
    else
      lib.concatMap references (builtins.attrValues value);
  trees = [
    cfg.settings
    cfg.auth.settings
  ];
in
{
  resolve = resolveAt false;
  settings = lib.mapAttrs (
    section: value:
    if
      builtins.elem section [
        "wodle"
        "localfile"
        "command"
        "gcp-pubsub"
        "gcp-bucket"
      ]
      && references value != [ ]
    then
      fail "${section} may pass text to subprocess arguments; use credentialFiles and the collector's profile/auth-file options instead of inline _secret references"
    else
      resolveAt false value
  ) cfg.settings;
  secrets = lib.listToAttrs (
    map (
      name:
      if !validName name || !(builtins.hasAttr name cfg.secretFiles) then
        fail "invalid or undefined structured secret reference"
      else
        lib.nameValuePair "settings-${name}" {
          source = cfg.secretFiles.${name};
          target = "config";
        }
    ) (lib.unique (lib.concatMap references trees))
  );
  credentialFiles = cfg.credentialFiles;
  inherit credentialPath;
}
