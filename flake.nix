{
  description = "Another Clash Kernel";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          packages = rec{
            clash-meta = pkgs.callPackage ./. { };
            default = clash-meta;
          };

          apps = rec {
            clash-meta = utils.lib.mkApp { drv = self.packages.${system}.clash-meta; };
            default = clash-meta;
          };
        }
      );
}

