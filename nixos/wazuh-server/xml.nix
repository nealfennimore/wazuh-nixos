# Wazuh uses OS_XML, not a standards-compliant XML reader: entities are
# literal strings. Preserve ampersands (commands and URLs need them), and
# reject text that would change the structure instead of escaping it.
{ lib }:
let
  fail = message: throw "services.wazuh-server.settings: ${message}";
  scalar =
    value:
    if builtins.isBool value then
      (if value then "yes" else "no")
    else if builtins.isString value || builtins.isInt value then
      toString value
    else
      fail "values must be strings, integers, booleans, lists or attribute sets";
  text =
    value:
    let
      s = scalar value;
    in
    if lib.hasInfix "<" s || lib.hasSuffix "\\" s then
      fail "text cannot contain '<' or end with a backslash (OS_XML cannot represent these)"
    else
      s;
  name =
    value:
    if builtins.match "[A-Za-z][A-Za-z0-9_.:-]*" value != null then
      value
    else
      fail "invalid element or attribute name '${value}'";
  attribute =
    value:
    let
      s = text value;
    in
    if lib.hasInfix "\"" s || lib.hasInfix ">" s || lib.hasInfix "\n" s || lib.hasInfix "\r" s then
      fail "attributes cannot contain quotes, angle brackets or newlines"
    else
      s;
  element =
    key: value:
    if value == null then
      ""
    else if builtins.isList value then
      lib.concatMapStrings (element key) value
    else
      let
        attrs = if builtins.isAttrs value then value._attributes or { } else { };
        children =
          if builtins.isAttrs value then
            builtins.removeAttrs value [
              "_attributes"
              "_text"
            ]
          else
            { };
        content =
          if !builtins.isAttrs value then
            text value
          else if value ? _text then
            if children != { } then
              fail "${key} cannot have both _text and child elements"
            else
              text value._text
          else
            render children;
        attributes =
          if !builtins.isAttrs attrs then
            fail "_attributes must be an attribute set"
          else
            lib.concatStrings (lib.mapAttrsToList (k: v: " ${name k}=\"${attribute v}\"") attrs);
      in
      "<${name key}${attributes}>${content}</${name key}>\n";
  render = values: lib.concatStrings (lib.mapAttrsToList element values);
in
{
  inherit render element;
}
