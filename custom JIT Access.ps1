[CmdletBinding()]
param (    
    [Parameter(Mandatory = $true)][string]$subscriptionId,
    [Parameter(Mandatory = $true)][string]$nsgname,
    [Parameter(Mandatory = $true)][string]$rgname,
    [Parameter(Mandatory = $false)][string]$ipaddress,
    [Parameter(Mandatory = $false)][string]$rulename = "CustomJIT_RDP"

)

function Login($SubscriptionId) {
    $context = Get-AzContext

    if (!$context -or ($context.Subscription.Id -ne $SubscriptionId)) {
        Write-Host "Login to subscription '$SubscriptionId' needed" -ForegroundColor Yellow    
        Connect-AzAccount -Subscription $SubscriptionId 
    } 
    else {
        Write-Host "SubscriptionId '$SubscriptionId' already connected" -ForegroundColor Green
    }
}
    
Login -SubscriptionId $subscriptionId

$nsg = Get-AzNetworkSecurityGroup -Name $nsgname -ResourceGroupName $rgname
if ($null -ne $nsg) {
    $rule = Get-AzNetworkSecurityRuleConfig -Name $rulename -NetworkSecurityGroup $nsg -ErrorAction SilentlyContinue
    if ($null -eq $rule) {
       
       if([string]::IsNullOrEmpty($ipaddress)){
            $ipaddress= (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content 
       }
        $rule = Add-AzNetworkSecurityRuleConfig -Name $rulename -NetworkSecurityGroup $nsg `
            -Access "Allow" `
            -Protocol "Tcp" `
            -Direction "Inbound" `
            -Priority "100" `
            -SourceAddressPrefix $ipaddress `
            -SourcePortRange * `
            -DestinationAddressPrefix * `
            -DestinationPortRange 3389

        Write-Host "RDP JIT Activated for $ipaddress" -ForegroundColor Green
    }
    else {
        $rule = Remove-AzNetworkSecurityRuleConfig -Name $rulename -NetworkSecurityGroup $nsg 
        Write-Host "Rule removed" -ForegroundColor Yellow
    }
    $nsg = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg
    $rule = $null
}
else {
    Write-Host "Network Security Group $nsgname not found"
}
