{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.05.tar.gz") {} }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.pkg-config
  ];
  buildInputs = [
    pkgs.cacert
    pkgs.rustup
    pkgs.postgresql             # psql binary + library for diesel
    pkgs.cargo-cross            # cross-compiling
    pkgs.diesel-cli             # diesel cli
    pkgs.jq                     # json query cli tool
  ];
  DOCKER_BUILDKIT = "1";
  NIX_STORE = "/nix/store";
}
