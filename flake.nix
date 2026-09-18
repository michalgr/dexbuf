{
  description = "dexbuf development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            android_sdk.accept_license = true;
            allowUnfree = true;
          };
        };

        androidComposition = pkgs.androidenv.composeAndroidPackages {
          buildToolsVersions = [ "34.0.0" ];
          platformVersions = [ "34" ];
          includeNDK = false;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.uv
            pkgs.jdk
            androidComposition.androidsdk
          ];

          env = {
            ANDROID_HOME = "${androidComposition.androidsdk}/libexec/android-sdk";
          };

          shellHook = ''
            export PATH="$ANDROID_HOME/build-tools/34.0.0:$PATH"
          '';
        };
      });
}
