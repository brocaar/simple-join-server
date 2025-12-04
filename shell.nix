{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz") {} }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.pkg-config
  ];
  buildInputs = [
    pkgs.cacert
    pkgs.rustup
    pkgs.postgresql             # psql binary + library for diesel
    pkgs.diesel-cli             # diesel cli
    pkgs.jq                     # json query cli tool
  ];
  shellHook = ''
    export PATH=$PATH:~/.cargo/bin
  '';
  DOCKER_BUILDKIT = "1";
  NIX_STORE = "/nix/store";
}
