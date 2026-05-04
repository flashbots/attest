{
  description = "Development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      devShells.x86_64-linux.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          cargo
          clippy
          rustc
          rustfmt
          pkg-config
        ];

        buildInputs = with pkgs; [
          tpm2-tss
          openssl
        ];
      };
    };
}
