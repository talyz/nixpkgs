{ stdenv, fetchFromGitLab, git, buildGoPackage }:

buildGoPackage rec {
  pname = "gitlab-workhorse";

  version = "8.10.0";

  src = fetchFromGitLab {
    owner = "gitlab-org";
    repo = "gitlab-workhorse";
    rev = "v${version}";
    sha256 = "11cfhh48dga5ghfcijb68gbx0nfr5bs3vvp2j1gam9ac37fpvk0x";
  };

  goPackagePath = "gitlab.com/gitlab-org/gitlab-workhorse";
  goDeps = ./deps.nix;
  buildInputs = [ git ];

  makeFlags = [ "PREFIX=$(out)" "VERSION=${version}" "GOCACHE=$(TMPDIR)/go-cache" ];

  postConfigure = ''
    rm -r "$NIX_BUILD_TOP/go/src/gitlab.com/gitlab-org/labkit/vendor"
  '';

  meta = with stdenv.lib; {
    homepage = http://www.gitlab.com/;
    platforms = platforms.unix;
    maintainers = with maintainers; [ fpletz globin ];
    license = licenses.mit;
  };
}
