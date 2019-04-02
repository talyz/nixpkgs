# This file originates from composer2nix

{ stdenv, pkgs, lib, makeWrapper, writeTextFile, fetchurl, php, unzip, composer }:

let
  buildPackage =
    { pname
    , src
    , composerLock
    , buildInputs ? []
    , symlinkDependencies ? false
    , executable ? false
    , removeComposerArtifacts ? false
    , postInstall ? ""
    , noDev ? false
    , unpackPhase ? "true"
    , buildPhase ? "true"
    , ...}@args:

    let
      buildZipPackage = { name, vendor, src }:
        stdenv.mkDerivation {
          inherit name vendor src;
          buildInputs = [ pkgs.unzip ];
          buildCommand = ''
            unzip $src
            baseDir=$(find . -mindepth 1 -maxdepth 1 -type d)
            cd $baseDir
            mkdir -p $out
            mv * $out
          '';
        };

      buildPackageList = map (pkg:
        let
          nameAndVendor = builtins.match "(.*)/(.*)" pkg.name;
        in
          buildZipPackage {
            vendor = builtins.elemAt nameAndVendor 0;
            name = builtins.elemAt nameAndVendor 1;
            src = builtins.fetchurl { inherit (pkg.dist) url; };
          });
      composerLockAttrs = lib.importJSON composerLock;
      packages = buildPackageList composerLockAttrs.packages;
      devPackages = buildPackageList composerLockAttrs.packages-dev;

      reconstructInstalled = writeTextFile {
        name = "reconstructinstalled.php";
        executable = true;
        text = ''
          #! ${php}/bin/php
          <?php
          if (file_exists($argv[1])) {
              $composerLockStr = file_get_contents($argv[1]);

              if ($composerLockStr === false) {
                  fwrite(STDERR, "Cannot open composer.lock contents\n");
                  exit(1);
              }

              $config = json_decode($composerLockStr, true);

              $allPackages = array_key_exists("packages", $config) ? $config["packages"] : array();

              ${lib.optionalString (!noDev) ''
              if (array_key_exists("packages-dev", $config)) {
                  $allPackages = array_merge($allPackages, $config["packages-dev"]);
              }
              ''}

              echo json_encode($allPackages, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
          } else {
              echo "[]";
          }
        '';
      };

      constructBin = writeTextFile {
        name = "constructbin.php";
        executable = true;
        text = ''
          #! ${php}/bin/php
          <?php
          $composerJSONStr = file_get_contents($argv[1]);

          if ($composerJSONStr === false) {
              fwrite(STDERR, 'Cannot open composer.json contents'.PHP_EOL);
              exit(1);
          }

          $config = json_decode($composerJSONStr, true);

          $binDir = array_key_exists('bin-dir', $config) ? $config['bin-dir'] : 'bin';

          if (array_key_exists('bin', $config)) {
              if (!file_exists('vendor/'.$binDir)) {
                  mkdir('vendor/'.$binDir);
              }

              foreach ($config['bin'] as $bin) {
                  symlink('../../'.$bin, 'vendor/'.$binDir.'/'.basename($bin));
              }
          }
        '';
      };

      bundleDependencies = dependencies:
        lib.concatMapStrings
          (dependency: ''
             mkdir -p "${dependency.vendor}"
             ${if symlinkDependencies then
               ''ln -s "${dependency}" "${dependency.vendor}/${dependency.name}"''
               else
               ''cp -a "${dependency}" "${dependency.vendor}/${dependency.name}"''
              }
            '')
          dependencies;

      extraArgs = removeAttrs args [ "name" "packages" "devPackages" "buildInputs" ];
    in
    stdenv.mkDerivation ({
      pname = "composer-${pname}";
      buildInputs = [ php composer ] ++ buildInputs;

      inherit unpackPhase buildPhase;

      installPhase = ''
        ${if executable then ''
          mkdir -p $out/share/php
          cp -a $src $out/share/php/$name
          chmod -R u+w $out/share/php/$name
          cd $out/share/php/$name
        '' else ''
          cp -a $src $out
          chmod -R u+w $out
          cd $out
        ''}

        # Remove unwanted files
        rm -f *.nix

        export HOME=$TMPDIR

        # Remove the provided vendor folder if it exists
        rm -Rf vendor

        # If there is no composer.lock file, compose a dummy file.
        # Otherwise, composer attempts to download the package.json file from
        # the registry which we do not want.
        if [ ! -f composer.lock ]
        then
            cat > composer.lock <<EOF
        {
            "packages": []
        }
        EOF
        fi

        # Reconstruct the installed.json file from the lock file
        mkdir -p vendor/composer
        ${reconstructInstalled} composer.lock > vendor/composer/installed.json

        # Copy or symlink the provided dependencies
        cd vendor
        ${bundleDependencies packages}
        ${lib.optionalString (!noDev) (bundleDependencies devPackages)}
        cd ..

        # Reconstruct autoload scripts
        # We use the optimize feature because Nix packages cannot change after they have been built
        # Using the dynamic loader for a Nix package is useless since there is nothing to dynamically reload.
        composer dump-autoload --optimize ${lib.optionalString noDev "--no-dev"}

        # Run the install step as a validation to confirm that everything works out as expected
        composer install --optimize-autoloader ${lib.optionalString noDev "--no-dev"}

        ${lib.optionalString executable ''
          # Reconstruct the bin/ folder if we deploy an executable project
          ${constructBin} composer.json
          ln -s $(pwd)/vendor/bin $out/bin
        ''}

        ${lib.optionalString (!symlinkDependencies) ''
          # Patch the shebangs if possible
          if [ -d $(pwd)/vendor/bin ]
          then
              # Look for all executables in bin/
              for i in $(pwd)/vendor/bin/*
              do
                  # Look for their location
                  realFile=$(readlink -f "$i")

                  # Restore write permissions
                  chmod u+wx "$(dirname "$realFile")"
                  chmod u+w "$realFile"

                  # Patch shebang
                  sed -e "s|#!/usr/bin/php|#!${php}/bin/php|" \
                      -e "s|#!/usr/bin/env php|#!${php}/bin/php|" \
                      "$realFile" > tmp
                  mv tmp "$realFile"
                  chmod u+x "$realFile"
              done
          fi
        ''}

        if [ "$removeComposerArtifacts" = "1" ]
        then
            # Remove composer stuff
            rm -f composer.json composer.lock
        fi

        # Execute post install hook
        runHook postInstall
    '';
  } // extraArgs);
in {
  composer = lib.makeOverridable composer;
  buildPackage = lib.makeOverridable buildPackage;
}
