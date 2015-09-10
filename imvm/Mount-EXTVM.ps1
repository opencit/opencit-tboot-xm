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
Mount-EXTVM -Path ./Cirros.vhd -DriveLetter Z: -Mount 
Mount-EXTVM -Path ./Cirros.vhd -DriveLetter Z: -Umount 
#>

Param(
[string]$Path,
[string]$DriveLetter,
[switch]$Mount,
[switch]$Umount
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
			Write-Host "disknumber : $DiskNumber"
			$GpOutput = Get-Partition -DiskNumber $DiskNumber | fl PartitionNumber | findstr "Number"
			#Exit
			#$Output = $Output | fl PartitionNumber
			#$Output = $Output | findstr "Number"
			Write-Host "get partition : $GpOutPut"
			$PartitionNumber = $GpOutput.Chars(18)
			#$PartitionNumber = 1
			if( [string]::IsNullOrEmpty($PartitionNumber) ) {
				Write-Host "couldn't get Partition number"
				UnmountImage $Path $DriveLetter
				Exit
			}			
			else {
				Write-Host "partition number : $PartitionNumber :"
			}

			Start-Sleep -s 2
			& $Ext2DsdDriver $DiskNumber $PartitionNumber $DriveLetter
			If($?)
			{
				"Mounted Successfully on drive " + $DriveLetter
			}
			Else
			{
				"Unable to assign drive letter"
				UnmountImage $Path $DriveLetter
			}
		}
		Else
		{
			"Unable to get the image info"
			UnmountImage $Path $DriveLetter
		}	
	}
	Else
	{
		"Unable to mount the image"
	}	
}

Function UnmountImage ($Path, $DriveLetter)
{
	Start-Sleep -s 2
	& $Ext2DsdDriver /umount $DriveLetter
	Dismount-VHD -Path $Path
}

Function Usage()
{
	Write-Host "Usage: Mount-EXTVM.ps1 <Path> <DriveLetter> <Mount or Umount>"
}

If($Mount)
{
	MountImage $Path $DriveLetter
}
Elseif($Umount)
{
	UnmountImage $Path $DriveLetter
}
Else
{
	Usage
}
