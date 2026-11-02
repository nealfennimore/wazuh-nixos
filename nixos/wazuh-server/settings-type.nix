{ lib }:
let
  inherit (lib) types;
  value = types.nullOr (
    types.oneOf [
      types.str
      types.int
      types.bool
      (types.listOf value)
      (types.attrsOf value)
    ]
  );
in
types.attrsOf value
