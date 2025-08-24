$SolutionDir = Split-Path -Parent -Path $PSScriptRoot;

& "$SolutionDir/../VpnHood/Pub/Core/PublishNuget.ps1" $PSScriptRoot;
