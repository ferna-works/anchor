{
  lib,
  fetchFromGitHub,
  buildGoModule,
  cometbftVersion,
}:
buildGoModule (finalAttrs: {
  pname = "cometbft";
  version = lib.removePrefix "v" cometbftVersion;

  src = fetchFromGitHub {
    owner = "cometbft";
    repo = "cometbft";
    rev = cometbftVersion;
    hash = "sha256-6urWcDEMrImxPfGnlTi3qhQtcowRG0fbhkRnIuY5huE=";
  };

  vendorHash = "sha256-zE2i1xXSrKRakgTrJ8KYvLUh7DTUr6mIhcTF3HsvnE8=";
  subPackages = ["cmd/cometbft"];
  doCheck = false;

  meta = {
    description = "Byzantine fault-tolerant, deterministic state machine replication engine; fork and successor to Tendermint Core";
    homepage = "https://github.com/cometbft/cometbft";
    changelog = "https://github.com/cometbft/cometbft/blob/v${finalAttrs.version}/CHANGELOG.md";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    mainProgram = "cometbft";
  };
})
