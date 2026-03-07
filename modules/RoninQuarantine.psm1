Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-RoninQuarantine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Config,
    [Parameter(Mandatory=$true)][string]$Mailbox,
    [Parameter(Mandatory=$true)][string]$MessageId,
    [Parameter(Mandatory=$true)][ValidateSet('MoveToJunk','MoveToQuarantineFolder','SoftDelete')][string]$Action,
    [switch]$DryRun
  )

  # Safe by default: DryRun should be true unless explicitly set to false
  $ops = New-Object System.Collections.Generic.List[object]

  # NOTE: This module provides a ready workflow skeleton and prints the Graph calls it would make.
  # Implementing token acquisition is environment-specific (client secret vs cert vs managed identity).
  # We keep it minimal & safe: no network calls on dry-run.

  $graph = $Config.graph
  if (-not $graph.tenantId -or -not $graph.clientId) {
    throw "Graph config missing tenantId/clientId in config\ronin.config.json"
  }

  $ops.Add([PSCustomObject]@{ step="Resolve user"; method="GET"; url="/users/$Mailbox" })
  $ops.Add([PSCustomObject]@{ step="Get message"; method="GET"; url="/users/$Mailbox/messages/$MessageId" })

  switch ($Action) {
    'MoveToJunk' {
      $ops.Add([PSCustomObject]@{ step="Move to Junk"; method="POST"; url="/users/$Mailbox/messages/$MessageId/move"; body=@{ destinationId="JunkEmail" } })
    }
    'MoveToQuarantineFolder' {
      $folder = $graph.quarantineFolderName
      if (-not $folder) { $folder = "Quarantine" }
      $ops.Add([PSCustomObject]@{ step="Ensure folder"; method="POST"; url="/users/$Mailbox/mailFolders"; body=@{ displayName=$folder } })
      $ops.Add([PSCustomObject]@{ step="Move to folder"; method="POST"; url="/users/$Mailbox/messages/$MessageId/move"; body=@{ destinationId=$folder } })
    }
    'SoftDelete' {
      $ops.Add([PSCustomObject]@{ step="Delete message"; method="DELETE"; url="/users/$Mailbox/messages/$MessageId" })
    }
  }

  if ($DryRun) {
    return [PSCustomObject]@{
      dryRun = $true
      action = $Action
      mailbox = $Mailbox
      messageId = $MessageId
      plannedOperations = $ops.ToArray()
      note = "Dry-run: no calls executed. Implement token acquisition + Invoke-RestMethod calls when ready."
    }
  }

  # If not dry-run, you'd:
  # 1) Acquire token: https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
  # 2) Call Graph: https://graph.microsoft.com/v1.0{url}
  throw "Non-dry-run execution is intentionally not implemented in the scaffold. Add token acquisition + REST calls carefully."
}

Export-ModuleMember -Function Invoke-RoninQuarantine
