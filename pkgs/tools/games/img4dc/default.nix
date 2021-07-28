{ stdenv, lib, fetchFromGitHub, cmake }:

stdenv.mkDerivation rec {
  name = "img4dc";
  nativeBuildInputs = [
    cmake
  ];
  src = fetchFromGitHub {
    owner = "Kazade";
    repo = name;
    rev = "afce20cd7f36d9bbb82013975b0e90e2fa221877";
    sha256 = "13dqfvskhnqkkm7lrdr1ba6s7f31fdpl2k8j0awha9ss0y60jgbh";
  };
  hardeningDisable = [ "format" ];
  installPhase = ''
    runHook preInstall

    install -D mds4dc/mds4dc cdi4dc/cdi4dc -t $out/bin

    runHook postInstall
  '';
}
