{ stdenv, lib, fetchFromGitHub }:

stdenv.mkDerivation rec {
  pname = "cdirip";
  version = "0.6.4";
  src = fetchFromGitHub {
    owner = "jozip";
    repo = "cdirip";
    rev = "v${version}";
    sha256 = "0a15rmcidcdvw15xm0sggzkwmigrw9lnf1y67g4zwrrn700k9r9p";
  };
  patches = [ ./output_path.patch ];
  # src = ./cdirip;
  hardeningDisable = [ "format" ];
  preInstall = ''
    mkdir -p $out/bin $out/include/cdirip
  '';
}
