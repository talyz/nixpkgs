{ config, lib, pkgs, ... }:

# TODO: support non-postgresql

with lib;

let
  cfg = config.services.gitlab;

  ruby = cfg.packages.gitlab.ruby;

  gitlabSocket = "${cfg.statePath}/tmp/sockets/gitlab.socket";
  gitalySocket = "${cfg.statePath}/tmp/sockets/gitaly.socket";
  pathUrlQuote = url: replaceStrings ["/"] ["%2F"] url;
  pgSuperUser = config.services.postgresql.superUser;

  databaseConfig = {
    production = {
      adapter = "postgresql";
      database = cfg.databaseName;
      host = cfg.databaseHost;
      username = cfg.databaseUsername;
      encoding = "utf8";
      pool = cfg.databasePool;
    } // cfg.extraDatabaseConfig;
  };

  gitalyToml = pkgs.writeText "gitaly.toml" ''
    socket_path = "${lib.escape ["\""] gitalySocket}"
    bin_dir = "${cfg.packages.gitaly}/bin"
    prometheus_listen_addr = "localhost:9236"

    [git]
    bin_path = "${pkgs.git}/bin/git"

    [gitaly-ruby]
    dir = "${cfg.packages.gitaly.ruby}"

    [gitlab-shell]
    dir = "${cfg.packages.gitlab-shell}"

    ${concatStringsSep "\n" (attrValues (mapAttrs (k: v: ''
    [[storage]]
    name = "${lib.escape ["\""] k}"
    path = "${lib.escape ["\""] v.path}"
    '') gitlabConfig.production.repositories.storages))}
  '';

  gitlabShellConfig = {
    user = cfg.user;
    gitlab_url = "http+unix://${pathUrlQuote gitlabSocket}";
    http_settings.self_signed_cert = false;
    repos_path = "${cfg.statePath}/repositories";
    secret_file = "${cfg.statePath}/gitlab_shell_secret";
    log_file = "${cfg.statePath}/log/gitlab-shell.log";
    custom_hooks_dir = "${cfg.statePath}/custom_hooks";
    redis = {
      bin = "${pkgs.redis}/bin/redis-cli";
      host = "127.0.0.1";
      port = 6379;
      database = 0;
      namespace = "resque:gitlab";
    };
  };

  redisConfig.production.url = "redis://localhost:6379/";

  gitlabConfig = {
    # These are the default settings from config/gitlab.example.yml
    production = flip recursiveUpdate cfg.extraConfig {
      gitlab = {
        host = cfg.host;
        port = cfg.port;
        https = cfg.https;
        user = cfg.user;
        email_enabled = true;
        email_display_name = "GitLab";
        email_reply_to = "noreply@localhost";
        default_theme = 2;
        default_projects_features = {
          issues = true;
          merge_requests = true;
          wiki = true;
          snippets = true;
          builds = true;
          container_registry = true;
        };
      };
      repositories.storages.default.path = "${cfg.statePath}/repositories";
      repositories.storages.default.gitaly_address = "unix:${gitalySocket}";
      artifacts.enabled = true;
      lfs.enabled = true;
      gravatar.enabled = true;
      cron_jobs = { };
      gitlab_ci.builds_path = "${cfg.statePath}/builds";
      ldap.enabled = false;
      omniauth.enabled = false;
      shared.path = "${cfg.statePath}/shared";
      gitaly.client_path = "${cfg.packages.gitaly}/bin";
      backup.path = "${cfg.backupPath}";
      gitlab_shell = {
        path = "${cfg.packages.gitlab-shell}";
        hooks_path = "${cfg.statePath}/shell/hooks";
        secret_file = "${cfg.statePath}/gitlab_shell_secret";
        upload_pack = true;
        receive_pack = true;
      };
      workhorse.secret_file = "${cfg.statePath}/.gitlab_workhorse_secret";
      git.bin_path = "git";
      monitoring = {
        ip_whitelist = [ "127.0.0.0/8" "::1/128" ];
        sidekiq_exporter = {
          enable = true;
          address = "localhost";
          port = 3807;
        };
      };
      extra = {};
      uploads.storage_path = cfg.statePath;
    };
  };

  gitlabEnv = {
    HOME = "${cfg.statePath}/home";
    UNICORN_PATH = "${cfg.statePath}/";
    GITLAB_PATH = "${cfg.packages.gitlab}/share/gitlab/";
    SCHEMA = "${cfg.statePath}/db/schema.rb";
    GITLAB_UPLOADS_PATH = "${cfg.statePath}/uploads";
    GITLAB_LOG_PATH = "${cfg.statePath}/log";
    GITLAB_REDIS_CONFIG_FILE = pkgs.writeText "redis.yml" (builtins.toJSON redisConfig);
    prometheus_multiproc_dir = "/run/gitlab";
    RAILS_ENV = "production";
  };

  gitlab-rake = pkgs.stdenv.mkDerivation rec {
    name = "gitlab-rake";
    buildInputs = [ pkgs.makeWrapper ];
    dontBuild = true;
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out/bin
      makeWrapper ${cfg.packages.gitlab.rubyEnv}/bin/rake $out/bin/gitlab-rake \
          ${concatStrings (mapAttrsToList (name: value: "--set ${name} '${value}' ") gitlabEnv)} \
          --set PATH '${lib.makeBinPath [ pkgs.nodejs pkgs.gzip pkgs.git pkgs.gnutar config.services.postgresql.package pkgs.coreutils pkgs.procps ]}:$PATH' \
          --set RAKEOPT '-f ${cfg.packages.gitlab}/share/gitlab/Rakefile' \
          --run 'cd ${cfg.packages.gitlab}/share/gitlab'
     '';
  };

  gitlab-rails = pkgs.stdenv.mkDerivation rec {
    name = "gitlab-rails";
    buildInputs = [ pkgs.makeWrapper ];
    dontBuild = true;
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out/bin
      makeWrapper ${cfg.packages.gitlab.rubyEnv}/bin/rails $out/bin/gitlab-rails \
          ${concatStrings (mapAttrsToList (name: value: "--set ${name} '${value}' ") gitlabEnv)} \
          --set PATH '${lib.makeBinPath [ pkgs.nodejs pkgs.gzip pkgs.git pkgs.gnutar config.services.postgresql.package pkgs.coreutils pkgs.procps ]}:$PATH' \
          --run 'cd ${cfg.packages.gitlab}/share/gitlab'
     '';
  };

  extraGitlabRb = pkgs.writeText "extra-gitlab.rb" cfg.extraGitlabRb;

  smtpSettings = pkgs.writeText "gitlab-smtp-settings.rb" ''
    if Rails.env.production?
      Rails.application.config.action_mailer.delivery_method = :smtp

      ActionMailer::Base.delivery_method = :smtp
      ActionMailer::Base.smtp_settings = {
        address: "${cfg.smtp.address}",
        port: ${toString cfg.smtp.port},
        ${optionalString (cfg.smtp.username != null) ''user_name: "${cfg.smtp.username}",''}
        ${optionalString (cfg.smtp.password != null) ''password: "${cfg.smtp.password}",''}
        ${optionalString (cfg.smtp.passwordFile != null) ''password: "@smtpPassword@",''}
        domain: "${cfg.smtp.domain}",
        ${optionalString (cfg.smtp.authentication != null) "authentication: :${cfg.smtp.authentication},"}
        enable_starttls_auto: ${toString cfg.smtp.enableStartTLSAuto},
        openssl_verify_mode: '${cfg.smtp.opensslVerifyMode}'
      }
    end
  '';

  # Recursively get attrs with a name matching the "attr" parameter.
  recursiveGetAttrWithJqPrefix = set: attr:
    let
      recurse = prefix: item:
        if item ? ${attr} then
          nameValuePair prefix item.${attr}
        else if isAttrs item then
          map (name: recurse (prefix + "." + name) item.${name}) (attrNames item)
        else if isList item then
          imap0 (index: item: recurse (prefix + "[${toString index}]") item) item
        else
          [];
    in listToAttrs (flatten (map (name: recurse name set.${name}) (attrNames set)));

  genSecretsReplacementSnippet = set: input: output:
      concatStringsSep
        "\n"
        (imap1 (index: name: "export secret${toString index}=$(<'${set.${name}}')")
               (attrNames set)) + "\n"
      + "${pkgs.jq}/bin/jq <'${input}' >'${output}' '"
      + concatStringsSep
          " | "
          (imap1 (index: name: ''.${name} = $ENV.secret${toString index}'')
                 (attrNames set)) + "'";

in {

  options = {
    services.gitlab = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable the gitlab service.
        '';
      };

      packages.gitlab = mkOption {
        type = types.package;
        default = pkgs.gitlab;
        defaultText = "pkgs.gitlab";
        description = "Reference to the gitlab package";
        example = "pkgs.gitlab-ee";
      };

      packages.gitlab-shell = mkOption {
        type = types.package;
        default = pkgs.gitlab-shell;
        defaultText = "pkgs.gitlab-shell";
        description = "Reference to the gitlab-shell package";
      };

      packages.gitlab-workhorse = mkOption {
        type = types.package;
        default = pkgs.gitlab-workhorse;
        defaultText = "pkgs.gitlab-workhorse";
        description = "Reference to the gitlab-workhorse package";
      };

      packages.gitaly = mkOption {
        type = types.package;
        default = pkgs.gitaly;
        defaultText = "pkgs.gitaly";
        description = "Reference to the gitaly package";
      };

      statePath = mkOption {
        type = types.str;
        default = "/var/gitlab/state";
        description = "Gitlab state directory, logs are stored here.";
      };

      backupPath = mkOption {
        type = types.str;
        default = cfg.statePath + "/backup";
        description = "Gitlab path for backups.";
      };

      databaseHost = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Gitlab database hostname.";
      };

      databasePassword = mkOption {
        type = with types; nullOr str;
        default = null;
        description = "Gitlab database user password.";
      };

      databasePasswordFile = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          File containing the Gitlab database user password. This
          should be a string, not a nix path, since they're copied
          into the nix store, defeating the purpose of using this over
          databasePassword.
        '';
      };

      databaseName = mkOption {
        type = types.str;
        default = "gitlab";
        description = "Gitlab database name.";
      };

      databaseUsername = mkOption {
        type = types.str;
        default = "gitlab";
        description = "Gitlab database user.";
      };

      databasePool = mkOption {
        type = types.int;
        default = 5;
        description = "Database connection pool size.";
      };

      extraDatabaseConfig = mkOption {
        type = types.attrs;
        default = {};
        description = "Extra configuration in config/database.yml.";
      };

      extraGitlabRb = mkOption {
        type = types.str;
        default = "";
        example = ''
          if Rails.env.production?
            Rails.application.config.action_mailer.delivery_method = :sendmail
            ActionMailer::Base.delivery_method = :sendmail
            ActionMailer::Base.sendmail_settings = {
              location: "/run/wrappers/bin/sendmail",
              arguments: "-i -t"
            }
          end
        '';
        description = ''
          Extra configuration to be placed in config/extra-gitlab.rb. This can
          be used to add configuration not otherwise exposed through this module's
          options.
        '';
      };

      host = mkOption {
        type = types.str;
        default = config.networking.hostName;
        description = "Gitlab host name. Used e.g. for copy-paste URLs.";
      };

      port = mkOption {
        type = types.int;
        default = 8080;
        description = ''
          Gitlab server port for copy-paste URLs, e.g. 80 or 443 if you're
          service over https.
        '';
      };

      https = mkOption {
        type = types.bool;
        default = false;
        description = "Whether gitlab prints URLs with https as scheme.";
      };

      user = mkOption {
        type = types.str;
        default = "gitlab";
        description = "User to run gitlab and all related services.";
      };

      group = mkOption {
        type = types.str;
        default = "gitlab";
        description = "Group to run gitlab and all related services.";
      };

      initialRootEmail = mkOption {
        type = types.str;
        default = "admin@local.host";
        description = ''
          Initial email address of the root account if this is a new install.
        '';
      };

      initialRootPassword = mkOption {
        type = with types; nullOr str;
        description = ''
          Initial password of the root account if this is a new install.
        '';
      };

      initialRootPasswordFile = mkOption {
        type = with types; nullOr str;
        description = ''
          File containing the initial password of the root account if
          this is a new install.
        '';
      };

      smtp = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Enable gitlab mail delivery over SMTP.";
        };

        address = mkOption {
          type = types.str;
          default = "localhost";
          description = "Address of the SMTP server for Gitlab.";
        };

        port = mkOption {
          type = types.int;
          default = 465;
          description = "Port of the SMTP server for Gitlab.";
        };

        username = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Username of the SMTP server for Gitlab.";
        };

        password = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Password of the SMTP server for Gitlab.";
        };

        passwordFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "File containing the password of the SMTP server for Gitlab.";
        };

        domain = mkOption {
          type = types.str;
          default = "localhost";
          description = "HELO domain to use for outgoing mail.";
        };

        authentication = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Authentitcation type to use, see http://api.rubyonrails.org/classes/ActionMailer/Base.html";
        };

        enableStartTLSAuto = mkOption {
          type = types.bool;
          default = true;
          description = "Whether to try to use StartTLS.";
        };

        opensslVerifyMode = mkOption {
          type = types.str;
          default = "peer";
          description = "How OpenSSL checks the certificate, see http://api.rubyonrails.org/classes/ActionMailer/Base.html";
        };
      };

      secrets.secret = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          The secret is used to encrypt variables in the DB. If
          you change or lose this key you will be unable to access variables
          stored in database.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.secretFile = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          A file containing the secret used to encrypt variables in
          the DB. If you change or lose this key you will be unable to
          access variables stored in database.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.db = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          The secret is used to encrypt variables in the DB. If
          you change or lose this key you will be unable to access variables
          stored in database.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.dbFile = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          A file containing the secret used to encrypt variables in
          the DB. If you change or lose this key you will be unable to
          access variables stored in database.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.otp = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          The secret is used to encrypt secrets for OTP tokens. If
          you change or lose this key, users which have 2FA enabled for login
          won't be able to login anymore.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.otpFile = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          A file containing the secret used to encrypt secrets for OTP
          tokens. If you change or lose this key, users which have 2FA
          enabled for login won't be able to login anymore.

          Make sure the secret is at least 30 characters and all random,
          no regular words or you'll be exposed to dictionary attacks.
        '';
      };

      secrets.jws = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          The secret is used to encrypt session keys. If you change or lose
          this key, users will be disconnected.

          Make sure the secret is an RSA private key in PEM format. You can
          generate one with

          openssl genrsa 2048
        '';
      };

      secrets.jwsFile = mkOption {
        type = with types; nullOr str;
        default = null;
        description = ''
          A file containing the secret used to encrypt session
          keys. If you change or lose this key, users will be
          disconnected.

          Make sure the secret is an RSA private key in PEM format. You can
          generate one with

          openssl genrsa 2048
        '';
      };

      extraConfig = mkOption {
        type = types.attrs;
        default = {};
        example = {
          gitlab = {
            default_projects_features = {
              builds = false;
            };
          };
        };
        description = ''
          Extra options to be merged into config/gitlab.yml as nix
          attribute set.

          Options containing secret data should be set to an attrset
          containing the attribute _secret pointing to a file
          containing the value the option should be set to.

        '';
      };
    };
  };

  config = mkIf cfg.enable {

    assertions = [
      {
        assertion = !((cfg.smtp.password != null) && (cfg.smtp.passwordFile != null));
        message = "Only one of services.gitlab.smtp.password or services.gitlab.smtpPasswordFile should be set.";
      }
      {
        assertion = (cfg.initialRootPassword != null) != (cfg.initialRootPasswordFile != null);
        message = "One and only one of services.gitlab.initialRootPassword or services.gitlab.initialRootPasswordFile should be set.";
      }
      {
        assertion = (cfg.databasePassword != null) != (cfg.databasePasswordFile != null);
        message = "One and only one of services.gitlab.databasePassword or services.gitlab.databasePasswordFile should be set.";
      }
      {
        assertion = (cfg.secrets.secret != null) != (cfg.secrets.secretFile != null);
        message = "One and only one of services.gitlab.secrets.secret or services.gitlab.secrets.secretFile should be set.";
      }
      {
        assertion = (cfg.secrets.db != null) != (cfg.secrets.dbFile != null);
        message = "One and only one of services.gitlab.secrets.db or services.gitlab.secrets.dbFile should be set.";
      }
      {
        assertion = (cfg.secrets.otp != null) != (cfg.secrets.otpFile != null);
        message = "One and only one of services.gitlab.secrets.otp or services.gitlab.secrets.otpFile should be set.";
      }
      {
        assertion = (cfg.secrets.jws != null) != (cfg.secrets.jwsFile != null);
        message = "One and only one of services.gitlab.secrets.jws or services.gitlab.secrets.jwsFile should be set.";
      }
    ];

    environment.systemPackages = [ pkgs.git gitlab-rake gitlab-rails cfg.packages.gitlab-shell ];

    # Redis is required for the sidekiq queue runner.
    services.redis.enable = mkDefault true;
    # We use postgres as the main data store.
    services.postgresql.enable = mkDefault true;
    # Use postfix to send out mails.
    services.postfix.enable = mkDefault true;

    users.users = [
      { name = cfg.user;
        group = cfg.group;
        home = "${cfg.statePath}/home";
        shell = "${pkgs.bash}/bin/bash";
        uid = config.ids.uids.gitlab;
      }
    ];

    users.groups = [
      { name = cfg.group;
        gid = config.ids.gids.gitlab;
      }
    ];

    systemd.tmpfiles.rules = [
      "d /run/gitlab 0755 ${cfg.user} ${cfg.group} -"
      "d ${gitlabEnv.HOME} 0750 ${cfg.user} ${cfg.group} -"
      "z ${gitlabEnv.HOME}/.ssh/authorized_keys 0600 ${cfg.user} ${cfg.group} -"
      "d ${cfg.backupPath} 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath} 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/builds 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/config 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/config/initializers 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/db 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/log 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/repositories 2770 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/shell 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/tmp 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/tmp/pids 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/tmp/sockets 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/uploads 0700 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/custom_hooks 0700 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/custom_hooks/pre-receive.d 0700 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/custom_hooks/post-receive.d 0700 ${cfg.user} ${cfg.group} -"
      "d ${cfg.statePath}/custom_hooks/update.d 0700 ${cfg.user} ${cfg.group} -"
      "d ${gitlabConfig.production.shared.path} 0750 ${cfg.user} ${cfg.group} -"
      "d ${gitlabConfig.production.shared.path}/artifacts 0750 ${cfg.user} ${cfg.group} -"
      "d ${gitlabConfig.production.shared.path}/lfs-objects 0750 ${cfg.user} ${cfg.group} -"
      "d ${gitlabConfig.production.shared.path}/pages 0750 ${cfg.user} ${cfg.group} -"
      "L+ ${cfg.statePath}/lib - - - - ${cfg.packages.gitlab}/share/gitlab/lib"
      "L+ /run/gitlab/config - - - - ${cfg.statePath}/config"
      "L+ /run/gitlab/log - - - - ${cfg.statePath}/log"
      "L+ /run/gitlab/tmp - - - - ${cfg.statePath}/tmp"
      "L+ /run/gitlab/uploads - - - - ${cfg.statePath}/uploads"

      "L+ /run/gitlab/shell-config.yml - - - - ${pkgs.writeText "config.yml" (builtins.toJSON gitlabShellConfig)}"

      "L+ ${cfg.statePath}/config/unicorn.rb - - - - ${./defaultUnicornConfig.rb}"
      "L+ ${cfg.statePath}/config/initializers/extra-gitlab.rb - - - - ${extraGitlabRb}"
    ];

    systemd.services.gitlab-sidekiq = {
      after = [ "network.target" "redis.service" "gitlab.service" ];
      wantedBy = [ "multi-user.target" ];
      environment = gitlabEnv;
      path = with pkgs; [
        config.services.postgresql.package
        gitAndTools.git
        ruby
        openssh
        nodejs
        gnupg
      ];
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        TimeoutSec = "infinity";
        Restart = "on-failure";
        WorkingDirectory = "${cfg.packages.gitlab}/share/gitlab";
        ExecStart="${cfg.packages.gitlab.rubyEnv}/bin/sidekiq -C \"${cfg.packages.gitlab}/share/gitlab/config/sidekiq_queues.yml\" -e production -P ${cfg.statePath}/tmp/sidekiq.pid";
      };
    };

    systemd.services.gitaly = {
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      path = with pkgs; [
        openssh
        procps  # See https://gitlab.com/gitlab-org/gitaly/issues/1562
        gitAndTools.git
        cfg.packages.gitaly.rubyEnv
        cfg.packages.gitaly.rubyEnv.wrappedRuby
        gzip
        bzip2
      ];
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        TimeoutSec = "infinity";
        Restart = "on-failure";
        WorkingDirectory = gitlabEnv.HOME;
        ExecStart = "${cfg.packages.gitaly}/bin/gitaly ${gitalyToml}";
      };
    };

    systemd.services.gitlab-workhorse = {
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      path = with pkgs; [
        exiftool
        gitAndTools.git
        gnutar
        gzip
        openssh
        gitlab-workhorse
      ];
      serviceConfig = {
        PermissionsStartOnly = true; # preStart must be run as root
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        TimeoutSec = "infinity";
        Restart = "on-failure";
        WorkingDirectory = gitlabEnv.HOME;
        ExecStart =
          "${cfg.packages.gitlab-workhorse}/bin/gitlab-workhorse "
          + "-listenUmask 0 "
          + "-listenNetwork unix "
          + "-listenAddr /run/gitlab/gitlab-workhorse.socket "
          + "-authSocket ${gitlabSocket} "
          + "-documentRoot ${cfg.packages.gitlab}/share/gitlab/public "
          + "-secretPath ${cfg.statePath}/.gitlab_workhorse_secret";
      };
    };

    systemd.services.gitlab = {
      after = [ "gitlab-workhorse.service" "gitaly.service" "network.target" "postgresql.service" "redis.service" ];
      requires = [ "gitlab-sidekiq.service" ];
      wantedBy = [ "multi-user.target" ];
      environment = gitlabEnv;
      path = with pkgs; [
        config.services.postgresql.package
        gitAndTools.git
        openssh
        nodejs
        procps
        gnupg
      ];
      preStart = ''
        cp -f ${cfg.packages.gitlab}/share/gitlab/VERSION ${cfg.statePath}/VERSION
        rm -rf ${cfg.statePath}/db/*
        cp -rf --no-preserve=mode ${cfg.packages.gitlab}/share/gitlab/config.dist/* ${cfg.statePath}/config
        cp -rf --no-preserve=mode ${cfg.packages.gitlab}/share/gitlab/db/* ${cfg.statePath}/db

        ${cfg.packages.gitlab-shell}/bin/install

        ${optionalString cfg.smtp.enable ''
          install -m u=rw ${smtpSettings} ${cfg.statePath}/config/initializers/smtp_settings.rb
          ${optionalString (cfg.smtp.passwordFile != null) ''
            smtp_password=$(<'${cfg.smtp.passwordFile}')
            ${pkgs.replace}/bin/replace-literal -e '@smtpPassword@' "$smtp_password" '${cfg.statePath}/config/initializers/smtp_settings.rb'
          ''}
        ''}

        (
          umask u=rwx,g=,o=

          ${pkgs.openssl}/bin/openssl rand -hex 32 > ${cfg.statePath}/gitlab_shell_secret

          ${genSecretsReplacementSnippet
              (recursiveGetAttrWithJqPrefix gitlabConfig "_secret")
              (pkgs.writeText "gitlab.yml" (builtins.toJSON gitlabConfig))
              "${cfg.statePath}/config/gitlab.yml"
          }

          export secret="${if cfg.secrets.secretFile != null then "$(<'${cfg.secrets.secretFile}')" else cfg.secrets.secret}"
          export db="${if cfg.secrets.dbFile != null then "$(<'${cfg.secrets.dbFile}')" else cfg.secrets.db}"
          export otp="${if cfg.secrets.otpFile != null then "$(<'${cfg.secrets.otpFile}')" else cfg.secrets.otp}"
          export jws="${if cfg.secrets.jwsFile != null then "$(<'${cfg.secrets.jwsFile}')" else cfg.secrets.jws}"
          ${pkgs.jq}/bin/jq -n '{production: {secret_key_base: $ENV.secret,
                                              otp_key_base: $ENV.db,
                                              db_key_base: $ENV.otp,
                                              openid_connect_signing_key: $ENV.jws}}' \
                            > '${cfg.statePath}/config/secrets.yml'
        )

        # We remove potentially broken links to old gitlab-shell versions
        rm -f ${cfg.statePath}/repositories/**/*.git/hooks

        ${pkgs.git}/bin/git config --global core.autocrlf "input"
      '';

      preStartFullPrivileges = ''
        umask u=rwx,g=,o=

        export db_password="${if cfg.databasePasswordFile != null then "$(<'${cfg.databasePasswordFile}')" else cfg.databasePassword}"

        ${pkgs.jq}/bin/jq <${pkgs.writeText "database.yml" (builtins.toJSON databaseConfig)} \
                          '.production.password = $ENV.db_password' \
                          >'${cfg.statePath}/config/database.yml' 
        chown ${cfg.user}:${cfg.group} '${cfg.statePath}/config/database.yml'

        if [ "${cfg.databaseHost}" = "127.0.0.1" ]; then
          if ! ${pkgs.sudo}/bin/sudo -u ${pgSuperUser} \
                 psql postgres -c "SELECT usename FROM pg_user WHERE usename = '${cfg.databaseUsername}'" | grep ${cfg.databaseUsername} > /dev/null
          then
            ${pkgs.sudo}/bin/sudo -u ${pgSuperUser} \
              psql postgres -c "CREATE ROLE ${cfg.databaseUsername} WITH LOGIN NOCREATEDB NOCREATEROLE ENCRYPTED PASSWORD '$db_password'"
          fi
          if ! ${pkgs.sudo}/bin/sudo -u ${pgSuperUser} \
                 psql postgres -c "SELECT datname FROM pg_database WHERE datname = '${cfg.databaseName}'" | grep ${cfg.databaseName} > /dev/null
          then
            ${pkgs.sudo}/bin/sudo -u ${pgSuperUser} ${config.services.postgresql.package}/bin/createdb --owner ${cfg.databaseUsername} ${cfg.databaseName}
          fi
          
          # enable required pg_trgm extension for gitlab
          ${pkgs.sudo}/bin/sudo -u ${pgSuperUser} psql ${cfg.databaseName} -c "CREATE EXTENSION IF NOT EXISTS pg_trgm"
        fi

        initial_root_password="${if cfg.initialRootPasswordFile != null then "$(<'${cfg.initialRootPasswordFile}')" else cfg.initialRootPassword}"
        ${pkgs.sudo}/bin/sudo -u ${cfg.user} \
          ${gitlab-rake}/bin/gitlab-rake gitlab:db:configure GITLAB_ROOT_PASSWORD='${cfg.initialRootPassword}' \
                                                             GITLAB_ROOT_EMAIL='${cfg.initialRootEmail}'
      '';

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        TimeoutSec = "infinity";
        Restart = "on-failure";
        WorkingDirectory = "${cfg.packages.gitlab}/share/gitlab";
        ExecStart = "${cfg.packages.gitlab.rubyEnv}/bin/unicorn -c ${cfg.statePath}/config/unicorn.rb -E production";
      };

    };

  };

  meta.doc = ./gitlab.xml;

}
