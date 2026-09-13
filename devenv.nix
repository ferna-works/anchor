{ pkgs, ... }:
{
  packages = [
    pkgs.just
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };
}
