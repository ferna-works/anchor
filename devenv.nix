{ pkgs, lib, ... }:
let
  cometbftVersion = "v0.38.26";
  cometbft = pkgs.callPackage ./nix/cometbft.nix { inherit cometbftVersion; };

  nodeIndices = lib.range 0 4;

  cometbftProcesses = lib.listToAttrs (
    map (i: {
      name = "cometbft${toString i}";
      value = {
        exec = "${./scripts/cometbft-run.sh} ${toString i}";
        cwd = toString ./.;
      };
    }) nodeIndices
  );

  anchordProcesses = lib.listToAttrs (
    map (i: {
      name = "anchord${toString i}";
      value = {
        exec = "${./scripts/anchord-run.sh} ${toString i}";
        cwd = toString ./.;
      };
    }) nodeIndices
  );
in
{
  packages = [
    pkgs.just
    pkgs.shellcheck
    pkgs.shfmt
    pkgs.yq-go
    cometbft
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  processes = cometbftProcesses // anchordProcesses;
}
