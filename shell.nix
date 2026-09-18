{ pkgs ? import <nixpkgs> {
    config = {
      android_sdk.accept_license = true;
      allowUnfree = true;
    };
  }
}:

let
  androidComposition = pkgs.androidenv.composeAndroidPackages {
    buildToolsVersions = [ "34.0.0" ];
    platformVersions = [ "34" ];
    includeNDK = false;
  };
in
pkgs.mkShell {
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
}
