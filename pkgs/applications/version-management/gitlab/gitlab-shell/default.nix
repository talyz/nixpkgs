{ stdenv, ruby, bundler, fetchFromGitLab, buildGoPackage, bundlerEnv }:

let
  version = "10.0.0";
  src = fetchFromGitLab {
    owner = "gitlab-org";
    repo = "gitlab-shell";
    rev = "v${version}";
    sha256 = "0n1llkb0jrqxm10l9wqmqxjycydqphgz0chbbf395d8pywyz826x";
  };
  rubyEnv = bundlerEnv {
    name = "gitlab-shell-env";
    inherit ruby;
    gemdir = ./.;
  };
  goPackage = buildGoPackage {
    pname = "gitlab-shell-go";
    inherit src version;

    patches = [ ./remove-hardcoded-locations.patch ];

    goPackagePath = "gitlab.com/gitlab-org/gitlab-shell";
    goDeps = ./deps.nix;

    postConfigure = ''
      rm -r "$NIX_BUILD_TOP/go/src/gitlab.com/gitlab-org/gitaly/vendor/"
    '';
  };
in
stdenv.mkDerivation {
  pname = "gitlab-shell";
  inherit src version;
  
  patches = [ ./remove-hardcoded-locations.patch ];

  buildInputs = [ rubyEnv.wrappedRuby ];

  dontBuild = true;

  installPhase = ''
      mkdir -p $out/
      cp -R . $out/
      cp ${goPackage.bin}/bin/* $out/bin/
  
      # # Nothing to install ATM for non-development but keeping the
      # # install command anyway in case that changes in the future:
      # export HOME=$(pwd)
      # bundle install -j4 --verbose --local --deployment --without development test
    '';

  # gitlab-shell will try to read its config relative to the source
  # code by default which doesn't work in nixos because it's a
  # read-only filesystem
  postPatch = ''
      substituteInPlace lib/gitlab_config.rb --replace \
         "File.join(ROOT_PATH, 'config.yml')" \
         "'/run/gitlab/shell-config.yml'"
    '';

  meta = with stdenv.lib; {
    description = "SSH access and repository management app for GitLab";
    homepage = http://www.gitlab.com/;
    platforms = platforms.unix;
    maintainers = with maintainers; [ fpletz globin ];
    license = licenses.mit;
  };
}
