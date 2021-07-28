{ stdenv
, lib
, fetchFromGitHub
, makeWrapper
, python
, cdrkit
, hexdump
, gnused
, unzip
, cdirip
, img4dc
}:

stdenv.mkDerivation {
  name = "dc-card-maker";

  #src = ./dc-card-maker-script;
  src = fetchFromGitHub {
    owner = "talyz";
    repo = "dc-card-maker-script";
    rev = "c9319e998aa0ad3f14a09fe27ba53e6ee1ee1fcb";
    sha256 = "1z2c0x6j5k18fxljvfyhhl8h573wm2pdnhfhyx7nkh795lhb6fkv";
  };

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ python ];

  installPhase =
    let
      runtimeDeps = lib.makeBinPath [
        cdrkit
        hexdump
        gnused
        unzip
        cdirip
        img4dc
      ];
    in
      ''
        runHook preInstall

        mkdir -p $out/bin
        cp -r * $out/bin

        wrapProgram "$out/bin/dc-card-maker.sh" --prefix PATH ":" ${runtimeDeps}

        runHook postInstall
      '';

}
