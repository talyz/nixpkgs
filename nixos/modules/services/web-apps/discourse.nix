{ config, options, lib, pkgs, utils, ... }:

let
  cfg = config.services.discourse;

  postgresqlPackage = if config.services.postgresql.enable then
                        config.services.postgresql.package
                      else
                        pkgs.postgresql;

  # We only want to create a database if we're actually going to connect to it.
  databaseActuallyCreateLocally = cfg.database.createLocally && cfg.database.host == null;

  discourseEnv = {
    HOME = "/run/discourse/home";
    RAILS_ENV = "production";
    UNICORN_LISTENER = "/run/discourse/sockets/unicorn.sock";
    UNICORN_SIDEKIQS = "1";
  };

  discourse-rake = pkgs.runCommandNoCC "discourse-rake" {
    nativeBuildInputs = [ pkgs.makeWrapper ];
  } ''
    mkdir -p $out/bin
    makeWrapper ${cfg.package.rubyEnv}/bin/rake $out/bin/discourse-rake \
        ${lib.concatStrings (lib.mapAttrsToList (name: value: "--set ${name} '${value}' ") discourseEnv)} \
        --prefix PATH : ${lib.makeBinPath [ pkgs.nodejs pkgs.gzip pkgs.git pkgs.gnutar pkgs.procps pkgs.utillinux pkgs.which pkgs.brotli postgresqlPackage ]} \
        --set RAKEOPT '-f ${cfg.package}/share/discourse/Rakefile' \
        --run 'cd ${cfg.package}/share/discourse'
  '';

  # Default config values are from `config/discourse_defaults.conf`
  # upstream.
  discourseConf = let
    config = lib.flip lib.recursiveUpdate cfg.extraConfig {
      db_pool = cfg.database.pool;
      db_timeout = 5000;
      db_connect_timeout = 5;
      db_socket = null;
      db_host = cfg.database.host;
      db_backup_host = null;
      db_port = null;
      db_backup_port = 5432;
      db_name = cfg.database.name;
      db_username = cfg.database.username;
      db_password = cfg.database.passwordFile;
      db_prepared_statements = false;
      db_replica_host = null;
      db_replica_port = null;
      db_advisory_locks = true;

      inherit (cfg) hostname;
      backup_hostname = null;

      smtp_address = cfg.smtp.address;
      smtp_port = cfg.smtp.port;
      smtp_domain = cfg.smtp.domain;
      smtp_user_name = cfg.smtp.username;
      smtp_password = cfg.smtp.passwordFile;
      smtp_authentication = cfg.smtp.authentication;
      smtp_enable_start_tls = cfg.smtp.enableStartTLSAuto;
      smtp_openssl_verify_mode = cfg.smtp.opensslVerifyMode;

      load_mini_profiler = true;
      mini_profiler_snapshots_period = 0;
      mini_profiler_snapshots_transport_url = null;
      mini_profiler_snapshots_transport_auth_key = null;

      cdn_url = null;
      cdn_origin_hostname = null;
      developer_emails = null;

      redis_host = cfg.redis.host;
      redis_port = 6379;
      redis_slave_host = null;
      redis_slave_port = 6379;
      redis_db = cfg.redis.dbNumber;
      redis_password = cfg.redis.passwordFile;
      redis_skip_client_commands = false;
      redis_use_ssl = cfg.redis.useSSL;

      message_bus_redis_enabled = false;
      message_bus_redis_host = "localhost";
      message_bus_redis_port = 6379;
      message_bus_redis_slave_host = null;
      message_bus_redis_slave_port = 6379;
      message_bus_redis_db = 0;
      message_bus_redis_password = null;
      message_bus_redis_skip_client_commands = false;

      enable_cors = false;
      cors_origin = "";
      serve_static_assets = false;
      sidekiq_workers = 5;
      rtl_css = false;
      connection_reaper_age = 30;
      connection_reaper_interval = 30;
      relative_url_root = null;
      message_bus_max_backlog_size = 100;
      secret_key_base = cfg.secretKeyBaseFile;
      fallback_assets_path = null;

      s3_bucket = null;
      s3_region = null;
      s3_access_key_id = null;
      s3_secret_access_key = null;
      s3_use_iam_profile = null;
      s3_cdn_url = null;
      s3_endpoint = null;
      s3_http_continue_timeout = null;
      s3_install_cors_rule = null;

      max_user_api_reqs_per_minute = 20;
      max_user_api_reqs_per_day = 2880;
      max_admin_api_reqs_per_key_per_minute = 60;
      max_reqs_per_ip_per_minute = 200;
      max_reqs_per_ip_per_10_seconds = 50;
      max_asset_reqs_per_ip_per_10_seconds = 200;
      max_reqs_per_ip_mode = "block";
      max_reqs_rate_limit_on_private = false;
      force_anonymous_min_queue_seconds = 1;
      force_anonymous_min_per_10_seconds = 3;
      background_requests_max_queue_length = 0.5;
      reject_message_bus_queue_seconds = 0.1;
      disable_search_queue_threshold = 1;
      max_old_rebakes_per_15_minutes = 300;
      max_logster_logs = 1000;
      refresh_maxmind_db_during_precompile_days = 2;
      maxmind_backup_path = null;
      maxmind_license_key = null;
      enable_performance_http_headers = false;
      enable_js_error_reporting = true;
      mini_scheduler_workers = 5;
      compress_anon_cache = false;
      anon_cache_store_threshold = 2;
      allowed_theme_repos = null;
      enable_email_sync_demon = false;
      max_digests_enqueued_per_30_mins_per_site = 10000;
    };

    discourseKeyValue = lib.generators.toKeyValue {
      mkKeyValue = lib.flip lib.generators.mkKeyValueDefault " = " {
        mkValueString = v: with builtins;
          if isInt      v then toString v
          else if isString   v then ''"${v}"''
          else if true  ==   v then "true"
          else if false ==   v then "false"
          else if null  ==   v then ""
          else if isFloat    v then lib.strings.floatToString v
          else throw "unsupported type: ${typeOf v}";
      };
    };
  in
    pkgs.writeText "discourse.conf" (discourseKeyValue config);
in
{
  options = {
    services.discourse = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Enable the discourse service.
        '';
      };

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.discourse;
        defaultText = "pkgs.discourse";
        description = ''
          The discourse package to use.
        '';
      };

      hostname = lib.mkOption {
        type = lib.types.str;
        default = config.networking.hostName;
        example = "discourse.example.com";
        description = ''
          The hostname to serve Discourse on.
        '';
      };

      secretKeyBaseFile = lib.mkOption {
        type = with lib.types; nullOr path;
        default = null;
        example = "/run/keys/secret_key_base";
        description = ''
          The path to a file containing the
          <literal>secret_key_base</literal> secret.

          Discourse uses <literal>secret_key_base</literal> to encrypt
          the cookie store, which contains session data, and to digest
          user auth tokens.

          Needs to be a 64 byte long string of hexadecimal
          characters. You can generate one by running

          <screen>
          <prompt>$ </prompt>openssl rand -hex 64 >/path/to/secret_key_base_file
          </screen>
        '';
      };

      extraConfig = lib.mkOption {
        type = lib.types.attrs;
        default = {};
        example = lib.literalExample ''
          {
            max_reqs_per_ip_per_minute = 300;
            max_reqs_per_ip_per_10_seconds = 60;
            max_asset_reqs_per_ip_per_10_seconds = 250;
            max_reqs_per_ip_mode = "warn+block";
          };
        '';
        description = ''
          Extra options to set in the
          <filename>discourse.conf</filename> file. Look in the <link
          xlink:href="https://github.com/discourse/discourse/blob/master/config/discourse_defaults.conf">discourse_defaults.conf</link>
          file in the upstream distribution to find available
          options. Setting an option to <literal>null</literal> means
          <quote>define variable, but leave right-hand side
          empty</quote>.
        '';
      };

      admin = {
        email = lib.mkOption {
          type = lib.types.str;
          example = "admin@example.com";
          description = ''
            The admin user email address.
          '';
        };

        username = lib.mkOption {
          type = lib.types.str;
          example = "admin";
          description = ''
            The admin user username.
          '';
        };

        fullName = lib.mkOption {
          type = lib.types.str;
          description = ''
            The admin user's full name.
          '';
        };

        passwordFile = lib.mkOption {
          type = lib.types.path;
          description = ''
            A path to a file containing the admin user's password.
          '';
        };
      };

      nginx = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = ''
            Whether an <literal>nginx</literal> virtual host should be
            set up to serve Discourse. Only disable if you're planning
            to use a different web server, which is not recommended.
          '';
        };

        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.nginxStable;
          defaultText = "pkgs.nginxStable";
          description = ''
            The nginx package to use.
          '';
        };

        sslCertificate = lib.mkOption {
          type = with lib.types; nullOr path;
          default = null;
          example = "/run/keys/ssl.cert";
          description = ''
            The path to the server SSL certificate. Set this to enable
            SSL.
          '';
        };

        sslCertificateKey = lib.mkOption {
          type = with lib.types; nullOr path;
          default = null;
          example = "/run/keys/ssl.key";
          description = ''
            The path to the server SSL certificate key. Set this to
            enable SSL.
          '';
        };
      };

      database = {
        pool = lib.mkOption {
          type = lib.types.int;
          default = 8;
          description = ''
            Database connection pool size.
          '';
        };

        host = lib.mkOption {
          type = with lib.types; nullOr str;
          default = null;
          description = ''
            Discourse database hostname. <literal>null</literal> means <quote>prefer
            local unix socket connection</quote>.
          '';
        };

        passwordFile = lib.mkOption {
          type = with lib.types; nullOr path;
          default = null;
          description = ''
            File containing the Discourse database user password.

            This should be a string, not a nix path, since nix paths are
            copied into the world-readable nix store.
          '';
        };

        createLocally = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = ''
            Whether a database should be automatically created on the
            local host. Set this to <literal>false</literal> if you plan
            on provisioning a local database yourself. This has no effect
            if <option>services.discourse.database.host</option> is customized.
          '';
        };

        name = lib.mkOption {
          type = lib.types.str;
          default = "discourse";
          description = ''
            Discourse database name.
          '';
        };

        username = lib.mkOption {
          type = lib.types.str;
          default = "discourse";
          description = ''
            Discourse database user.
          '';
        };
      };

      redis = {
        host = lib.mkOption {
          type = lib.types.str;
          default = "localhost";
          description = ''
            Redis server hostname.
          '';
        };

        passwordFile = lib.mkOption {
          type = with lib.types; nullOr path;
          default = null;
          description = ''
            File containing the Redis password.

            This should be a string, not a nix path, since nix paths are
            copied into the world-readable nix store.
          '';
        };

        dbNumber = lib.mkOption {
          type = lib.types.int;
          default = 0;
          description = ''
            Redis database number.
          '';
        };

        useSSL = lib.mkOption {
          type = lib.types.bool;
          default = cfg.redis.host != "localhost";
          description = ''
            Connect to Redis with SSL.
          '';
        };
      };

      smtp = {
        address = lib.mkOption {
          type = lib.types.str;
          default = "localhost";
          description = ''
            The address of the SMTP server Discourse should use to
            send email.
          '';
        };

        port = lib.mkOption {
          type = lib.types.int;
          default = 25;
          description = ''
            The port of the SMTP server Discourse should use to
            send email.
          '';
        };

        username = lib.mkOption {
          type = with lib.types; nullOr str;
          default = null;
          description = ''
            The username of the SMTP server.
          '';
        };

        passwordFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          description = ''
            A file containing the password of the SMTP server account.

            This should be a string, not a nix path, since nix paths
            are copied into the world-readable nix store.
          '';
        };

        domain = lib.mkOption {
          type = lib.types.str;
          default = "localhost";
          description = ''
            HELO domain to use for outgoing mail.
          '';
        };

        authentication = lib.mkOption {
          type = with lib.types; nullOr (enum ["plain" "login" "cram_md5"]);
          default = null;
          description = ''
            Authentication type to use, see http://api.rubyonrails.org/classes/ActionMailer/Base.html
          '';
        };

        enableStartTLSAuto = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = ''
            Whether to try to use StartTLS.
          '';
        };

        opensslVerifyMode = lib.mkOption {
          type = lib.types.str;
          default = "peer";
          description = ''
            How OpenSSL checks the certificate, see http://api.rubyonrails.org/classes/ActionMailer/Base.html
          '';
        };
      };

    };
  };

  config = lib.mkIf cfg.enable {
    services.redis.enable = lib.mkDefault (cfg.redis.host == "localhost");

    services.postgresql = lib.mkIf databaseActuallyCreateLocally {
      enable = true;
      ensureUsers = [{ name = cfg.database.username; }];
    };

    # The postgresql module doesn't currently support concepts like
    # objects owners and extensions; for now we tack on what's needed
    # here.
    systemd.services.discourse-postgresql =
      let
        pgsql = config.services.postgresql;
      in
        lib.mkIf databaseActuallyCreateLocally {
          after = [ "postgresql.service" ];
          bindsTo = [ "postgresql.service" ];
          wantedBy = [ "discourse.service" ];
          partOf = [ "discourse.service" ];
          path = [
            pgsql.package
          ];
          script = ''
            set -o pipefail -o nounset -o errtrace -o errexit
            shopt -s inherit_errexit

            psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'discourse'" | grep -q 1 || psql -tAc 'CREATE DATABASE "discourse" OWNER "discourse"'
            psql '${cfg.database.name}' -tAc "CREATE EXTENSION IF NOT EXISTS pg_trgm"
            psql '${cfg.database.name}' -tAc "CREATE EXTENSION IF NOT EXISTS hstore"
          '';

          serviceConfig = {
            User = pgsql.superUser;
            Type = "oneshot";
            RemainAfterExit = true;
          };
        };

    systemd.services.discourse = {
      wantedBy = [ "multi-user.target" ];
      after = [
        "redis.service"
        "postgresql.service"
        "discourse-postgresql.service"
      ];
      bindsTo = [
        "redis.service"
      ] ++ lib.optionals (cfg.database.host == null) [
        "postgresql.service"
        "discourse-postgresql.service"
      ];
      path = [
        pkgs.gawk
        pkgs.procps
        pkgs.util-linux
        discourse-rake
        pkgs.imagemagick
        pkgs.optipng
        pkgs.pngquant
        pkgs.libjpeg
        pkgs.jpegoptim
        pkgs.gifsicle
        pkgs.nodePackages.svgo
        pkgs.replace
      ];
      environment = discourseEnv;
      serviceConfig = {
        Type = "simple";
        User = "discourse";
        Group = "discourse";
        DynamicUser = true;
        RuntimeDirectory = map (p: "discourse/" + p) [
          "config"
          "home"
          "tmp"
          "assets/javascripts/plugins"
          "public"
          "sockets"
        ];
        RuntimeDirectoryMode = 0755;
        LogsDirectory = "discourse";
        TimeoutSec = "infinity";
        Restart = "on-failure";
        WorkingDirectory = "${cfg.package}/share/discourse";

        ExecStartPre =
          let
            mkSecretReplacement = file:
              lib.optionalString (file != null) ''
                (
                    password=$(<'${file}')
                    replace-literal -fe '${file}' "$password" /run/discourse/config/discourse.conf
                )
              '';
            startPreFullPrivileges = ''
              set -o pipefail -o nounset -o errtrace -o errexit
              shopt -s inherit_errexit

              install -T -m 0400 -o discourse -g discourse '${cfg.admin.passwordFile}' /run/discourse/config/admin_password
              install -T -m 0400 -o discourse -g discourse ${discourseConf} /run/discourse/config/discourse.conf
              ${mkSecretReplacement cfg.database.passwordFile}
              ${mkSecretReplacement cfg.smtp.passwordFile}
              ${mkSecretReplacement cfg.redis.passwordFile}
              ${mkSecretReplacement cfg.secretKeyBaseFile}
            '';
            startPre = ''
              set -o pipefail -o nounset -o errtrace -o errexit
              shopt -s inherit_errexit

              cp -r ${cfg.package}/share/discourse/config.dist/* /run/discourse/config/
              cp -r ${cfg.package}/share/discourse/public.dist/* /run/discourse/public/

              (
                  umask u=rwx,g=,o=

                  discourse-rake db:migrate >>/var/log/discourse/db_migration.log
                  rm -rf /run/discourse/tmp/*

                  export ADMIN_EMAIL="${cfg.admin.email}"
                  export ADMIN_NAME="${cfg.admin.fullName}"
                  export ADMIN_USERNAME="${cfg.admin.username}"
                  export ADMIN_PASSWORD="$(</run/discourse/config/admin_password)"
                  rm -f /run/discourse/config/admin_password

                  discourse-rake admin:create_noninteractively
                  rm -rf /run/discourse/tmp/*
              )
            '';
          in [
            "+${pkgs.writeShellScript "discourse-start-pre-full-privileges" startPreFullPrivileges}"
            "${pkgs.writeShellScript "discourse-start-pre" startPre}"
          ];

        ExecStart = "${cfg.package.rubyEnv}/bin/bundle exec config/unicorn_launcher -E production -c config/unicorn.conf.rb";
      };
    };

    services.nginx = lib.mkIf cfg.nginx.enable {
      enable = true;
      package = cfg.nginx.package.override {
        modules = cfg.nginx.package.modules ++ [ pkgs.nginxModules.brotli ];
      };

      recommendedTlsSettings = true;
      recommendedOptimisation = true;
      recommendedGzipSettings = true;
      recommendedProxySettings = true;

      upstreams.discourse.servers."unix:/run/discourse/sockets/unicorn.sock" = {};

      appendHttpConfig = ''
        # inactive means we keep stuff around for 1440m minutes regardless of last access (1 week)
        # levels means it is a 2 deep heirarchy cause we can have lots of files
        # max_size limits the size of the cache
        proxy_cache_path /var/cache/nginx inactive=1440m levels=1:2 keys_zone=discourse:10m max_size=600m;

        # see: https://meta.discourse.org/t/x/74060
        proxy_buffer_size 8k;
      '';

      virtualHosts.${cfg.hostname} = {
        inherit (cfg.nginx) sslCertificate sslCertificateKey;
        forceSSL = lib.mkDefault (cfg.nginx.sslCertificate != null || cfg.nginx.sslCertificateKey != null);

        root = "/run/discourse/public";

        locations = {
          "/".tryFiles = "$uri @discourse";
          "@discourse" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
            '';
          };
          "^~ /backups/".extraConfig = ''
            internal;
          '';
          "/favicon.ico" = {
            return = "204";
            extraConfig = ''
              access_log off;
              log_not_found off;
            '';
          };
          "~ ^/uploads/short-url/" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
            '';
          };
          "~ ^/secure-media-uploads/" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
            '';
          };
          "~* (fonts|assets|plugins|uploads)/.*\.(eot|ttf|woff|woff2|ico|otf)$".extraConfig = ''
            expires 1y;
            add_header Cache-Control public,immutable;
            add_header Access-Control-Allow-Origin *;
          '';
          "/srv/status" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              access_log off;
              log_not_found off;
              proxy_set_header X-Request-Start "t=''${msec}";
            '';
          };
          "~ ^/javascripts/".extraConfig = ''
            expires 1d;
            add_header Cache-Control public,immutable;
          '';
          "~ ^/assets/(?<asset_path>.+)$".extraConfig = ''
            expires 1y;
            # asset pipeline enables this
            brotli_static on;
            gzip_static on;
            add_header Cache-Control public,immutable;
          '';
          "~ ^/plugins/".extraConfig = ''
            expires 1y;
            add_header Cache-Control public,immutable;
          '';
          "~ /images/emoji/".extraConfig = ''
            expires 1y;
            add_header Cache-Control public,immutable;
          '';
          "~ ^/uploads/" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
              proxy_set_header X-Sendfile-Type X-Accel-Redirect;
              proxy_set_header X-Accel-Mapping /run/discourse/public/=/downloads/;
              expires 1y;
              add_header Cache-Control public,immutable;

              # custom CSS
              location ~ /stylesheet-cache/ {
                  try_files $uri =404;
              }
              # this allows us to bypass rails
              location ~* \.(gif|png|jpg|jpeg|bmp|tif|tiff|ico|webp)$ {
                  try_files $uri =404;
              }
              # SVG needs an extra header attached
              location ~* \.(svg)$ {
              }
              # thumbnails & optimized images
              location ~ /_?optimized/ {
                  try_files $uri =404;
              }
            '';
          };
          "~ ^/admin/backups/" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
              proxy_set_header X-Sendfile-Type X-Accel-Redirect;
              proxy_set_header X-Accel-Mapping /run/discourse/public/=/downloads/;
            '';
          };
          "~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|highlight-js|stylesheets|theme-javascripts|favicon/proxied|service-worker)" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";

              # if Set-Cookie is in the response nothing gets cached
              # this is double bad cause we are not passing last modified in
              proxy_ignore_headers "Set-Cookie";
              proxy_hide_header "Set-Cookie";
              proxy_hide_header "X-Discourse-Username";
              proxy_hide_header "X-Runtime";

              # note x-accel-redirect can not be used with proxy_cache
              proxy_cache discourse;
              proxy_cache_key "$scheme,$host,$request_uri";
              proxy_cache_valid 200 301 302 7d;
              proxy_cache_valid any 1m;
            '';
          };
          "/message-bus/" = {
            proxyPass = "http://discourse";
            extraConfig = ''
              proxy_set_header X-Request-Start "t=''${msec}";
              proxy_http_version 1.1;
              proxy_buffering off;
            '';
          };
          "/downloads/".extraConfig = ''
            internal;
            alias /run/discourse/public/;
          '';
        };
      };
    };
  };
}
