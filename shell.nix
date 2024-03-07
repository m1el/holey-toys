{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell rec {
  buildInputs = with pkgs; [
    clang
  ];
  shellHook = ''
    export CC=clang
  '';
}
