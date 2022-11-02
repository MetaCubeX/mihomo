{
  description = "Another Clash Kernel";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlay ];
          };
        in
        rec {
          packages.default = pkgs.clash-meta;
        }
      ) //
    (
      let version = nixpkgs.lib.substring 0 8 self.lastModifiedDate or self.lastModified or "19700101"; in
      {
        overlay = final: prev: {

          clash-meta = final.buildGoModule {
            pname = "clash-meta";
            inherit version;
            src = ./.;

            vendorSha256 = "sha256-yhq4WHQcS4CrdcO6KJ5tSn4m7l5g1lNgE9/2BWd9Iys=";

            # Do not build testing suit
            excludedPackages = [ "./test" ];

            CGO_ENABLED = 0;

            ldflags = [
              "-s"
              "-w"
              "-X github.com/Dreamacro/clash/constant.Version=dev-${version}"
              "-X github.com/Dreamacro/clash/constant.BuildTime=${version}"
            ];
            
            tags = [
              "with_gvisor"
            ];

            # Network required 
            doCheck = false;

            postInstall = ''
              mv $out/bin/clash $out/bin/clash-meta
            '';

          };
        };
      }
    );
}

