{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
      nightly = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          nightly
          bpf-linker
          cargo-generate
          bpftools
          tcpdump
          wireshark
          wireshark-cli
        ];
      };
    };
}
