{ pkgs }: {
  deps = [
    pkgs.python311
    pkgs.python311Packages.pip
    pkgs.git          # the agent clones reference code from GitHub
    pkgs.curl
    pkgs.gnugrep
    pkgs.nodejs_20    # so the agent can run JavaScript it finds
  ];
}
