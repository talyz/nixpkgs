{ stdenv, lib, callPackage, fetchFromGitHub, bundlerEnv, ruby, replace
, redis, postgresql, which, brotli, procps, nodePackages, v8
}:
let
  version = "2.6.3";

  src = fetchFromGitHub {
    owner = "discourse";
    repo = "discourse";
    rev = "v${version}";
    sha256 = "06ykn53m7mmdk71szk86nlq87rspqlb3fjpdmqi133z63dbj20ll";
  };

  rubyEnv = bundlerEnv {
    name = "discourse-ruby-env-${version}";
    inherit version ruby;
    gemdir = ./rubyEnv;
    gemset =
      let
        gems = import ./rubyEnv/gemset.nix;
      in
        gems // {
          mini_racer = gems.mini_racer // {
            buildInputs = [ v8 ];
            dontBuild = false;

            # The Ruby extension makefile generator assumes the source
            # is C, when it's actually C++ ¯\_(ツ)_/¯
            postPatch = ''
              substituteInPlace ext/mini_racer_extension/extconf.rb \
                --replace '" -std=c++0x"' \
                          '" -x c++ -std=c++0x"'
            '';
          };
        };

    groups = [
      "default" "assets" "development" "test"
    ];
  };

  assets = stdenv.mkDerivation {
    pname = "discourse-assets";
    inherit version src;

    nativeBuildInputs = [
      rubyEnv.wrappedRuby
      postgresql
      redis
      which
      brotli
      procps
      nodePackages.uglify-js
    ];

    # We have to set up an environment that is close enough to
    # production ready or the assets:precompile task refuses to
    # run. This means that Redis and PostgreSQL has to be running and
    # database migrations performed.
    preBuild = ''
      redis-server >/dev/null &

      initdb -A trust $NIX_BUILD_TOP/postgres >/dev/null
      postgres -D $NIX_BUILD_TOP/postgres -k $NIX_BUILD_TOP >/dev/null &
      export PGHOST=$NIX_BUILD_TOP

      echo "Waiting for Redis and PostgreSQL to be ready.."
      while ! redis-cli --scan >/dev/null || ! psql -l >/dev/null; do
        sleep 0.1
      done

      psql -d postgres -tAc 'CREATE USER "discourse"'
      psql -d postgres -tAc 'CREATE DATABASE "discourse" OWNER "discourse"'
      psql 'discourse' -tAc "CREATE EXTENSION IF NOT EXISTS pg_trgm"
      psql 'discourse' -tAc "CREATE EXTENSION IF NOT EXISTS hstore"

      # Create a temporary home dir to stop bundler from complaining
      mkdir $NIX_BUILD_TOP/tmp_home
      export HOME=$NIX_BUILD_TOP/tmp_home

      export RAILS_ENV=production

      bundle exec rake db:migrate >/dev/null
      rm -r tmp/*
    '';

    buildPhase = ''
      runHook preBuild

      bundle exec rake assets:precompile

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      mv public/assets $out

      runHook postInstall
    '';
  };

in
stdenv.mkDerivation {
  pname = "discourse";
  inherit version src;

  buildInputs = [
    rubyEnv rubyEnv.wrappedRuby rubyEnv.bundler
  ];

  patches = [
    # Add a noninteractive admin creation task
    ./admin_create.patch

    # Disable jhead, which is currently marked as vulnerable
    ./disable_jhead.patch

    # Add the path to the CA cert bundle to make TLS work
    ./action_mailer_ca_cert.patch
  ];

  postPatch = ''
    # Always require lib-files and application.rb through their store
    # path, not their relative state directory path. This gets rid of
    # warnings and means we don't have to link back to lib from the
    # state directory.
    find config -type f -execdir sed -Ei "s,(\.\./)+(lib|app)/,$out/share/discourse/\2/," {} \;

    ${replace}/bin/replace-literal -f -r -e 'File.rename(temp_destination, destination)' "FileUtils.mv(temp_destination, destination)" .
  '';

  buildPhase = ''
    runHook preBuild

    mv config config.dist
    mv public public.dist

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/share
    cp -r . $out/share/discourse
    rm -r $out/share/discourse/log
    ln -sf /var/log/discourse $out/share/discourse/log
    ln -sf /run/discourse/tmp $out/share/discourse/tmp
    ln -sf /run/discourse/config $out/share/discourse/config
    ln -sf /run/discourse/assets/javascripts/plugins $out/share/discourse/app/assets/javascripts/plugins
    ln -sf /run/discourse/public $out/share/discourse/public
    ln -sf ${assets} $out/share/discourse/public.dist/assets

    runHook postInstall
  '';

  meta = with lib; {
    homepage = "https://www.discourse.org/";
    platforms = platforms.linux;
    maintainers = with maintainers; [ talyz ];
    license = licenses.gpl2Plus;
    description = "Discourse is an open source discussion platform";
  };

  passthru = {
    inherit rubyEnv;
    ruby = rubyEnv.wrappedRuby;
  };
}
