{ lib
, fetchFromGitHub
, buildGoModule
}:
buildGoModule rec {
  pname = "clash-meta";
  version = "1.13.1";

  src = fetchFromGitHub {
    owner = "MetaCubeX";
    repo = "Clash.Meta";
    rev = "1684756b79a232ee8f875bcfd87371f5c0ef066b";
    sha256 = "sha256-7g/Wcll0w4EhPI+KodtLHINqaR2larQNnP9YAsgNiN4=";
  };

  vendorSha256 = "sha256-7HjYcoqWA5gvPUc5psCgy0UTc17CBzBJ/OiGvII/iBA=";

  # Do not build testing suit
  excludedPackages = [ "./test" ];

  CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X github.com/Dreamacro/clash/constant.Version=${version}"
  ];

  # network required
  doCheck = false;

  postInstall = ''
    mv $out/bin/clash $out/bin/clash-meta
  '';

  meta = with lib; {
    description = "Another Clash Kernel";
    homepage = "https://github.com/MetaCubeX/Clash.Meta";
    license = licenses.gpl3Only;
  };
}
