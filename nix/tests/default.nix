{ self, pkgs }:

{
  full-workflow = import ./full-workflow.nix { inherit self pkgs; };
}
