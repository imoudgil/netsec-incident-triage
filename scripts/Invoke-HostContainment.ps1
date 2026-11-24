# Dry-run host containment recommendations (default -WhatIf). No live firewall changes without a ticket.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$HostAddress,

    [string]$Reason = 'SOC triage recommendation'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ContainmentPlan {
    param([string]$Ip)
    [pscustomobject]@{
        Host          = $Ip
        WindowsRule   = "New-NetFirewallRule -DisplayName 'SOC-Isolate-$Ip' -Direction Inbound -Action Block -RemoteAddress Any"
        LinuxIptables = "iptables -A INPUT -s 0.0.0.0/0 -d $Ip -j DROP  # analyst review required"
        TicketRequired = $true
    }
}

$plan = Get-ContainmentPlan -Ip $HostAddress

if ($PSCmdlet.ShouldProcess($HostAddress, "Log containment plan for $Reason")) {
    Write-Output "=== CONTAINMENT DRY-RUN ==="
    Write-Output "Host: $($plan.Host)"
    Write-Output "Windows: $($plan.WindowsRule)"
    Write-Output "Linux: $($plan.LinuxIptables)"
    Write-Output "Change ticket required before applying: $($plan.TicketRequired)"
}