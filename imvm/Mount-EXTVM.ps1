<#
.SYNOPSIS
Mounts/Unmounts VM image
.DESCRIPTION
This is used to mount/unmount EXT2/3 filesystem image on Windows host.
.PARAMETER Path
The path of the image you want to mount/ummount.
.PARAMETER DriveLetter
The drive letter to be assigned to the image.
.EXAMPLE
Mount-EXTVM -Mount -Path ./Cirros.vhd -DriveLetter Z:
Mount-EXTVM -Path ./Cirros.vhd
#>

Param(
[Parameter(Mandatory=$True)]
[string]$Path,

[string]$DriveLetter
)

$Ext2DsdDriver='C:\Program Files\Ext2Fsd\Mount.exe'

Function MountImage ($Path, $DriveLetter)
{
	Write-Host "path : $Path driveletter : $DriveLetter"
	Mount-VHD -Path $Path
	If($?)
	{
		$Output = Get-VHD -Path $Path | findstr DiskNumber
		If($?)
		{
			$DiskNumber = [Convert]::ToUInt32($Output.Substring(25+1))
			Write-Host "\ndisknumber : $DiskNumber"
			$GpOutput = Get-Partition -DiskNumber $DiskNumber | fl PartitionNumber | findstr "Number"
			#Exit
			#$Output = $Output | fl PartitionNumber
			#$Output = $Output | findstr "Number"
			Write-Host "get partition : $GpOutPut"
			$PartitionNumber = $GpOutput.Chars(18)
			#$PartitionNumber = 1
			if( [string]::IsNullOrEmpty($PartitionNumber) ) {
				Write-Host "couldn't get Partition number"
				UnmountImage($Path)
				Exit
			}			
			else {
				Write-Host "partition number : $PartitionNumber :"
			}
			Start-Sleep -s 2
			& $Ext2DsdDriver $DiskNumber $PartitionNumber $DriveLetter | Out-Null
			If($?)
			{
				"Mounted Successfully on drive " + $DriveLetter
			}
			Else
			{
				"Unable to assign drive letter"
				UnmountImage $Path
			}
		}
		Else
		{
			"Unable to get the image info"
			UnmountImage $Path
		}
		
	}
	Else
	{
		"Unable to mount the image"
	}
	
}

Function UnmountImage($Path)
{
	Dismount-VHD -Path $Path
}

If([bool]$DriveLetter)
{
	MountImage $Path $DriveLetter
}
Else
{
	UnmountImage $Path
}