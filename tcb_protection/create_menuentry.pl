#!/usr/bin/perl

print $ARGV[0]."\n";   # output file 
print $ARGV[1]."\n";	  # kernel name
print $ARGV[2]."\n";   # initrd name
print $ARGV[3]."\n";	  # kernel arg
print $ARGV[4]."\n";	  # Menuentry name prefix
print $ARGV[5]."\n";	#GRUB File Path
print $ARGV[6]."\n";	#Grub Version
print $ARGV[7]."\n";	#Tpm Version

$output_file = $ARGV[0];
$kernel_version = $ARGV[1];
$initrd_name = $ARGV[2];
$kernel_arg = $ARGV[3];
$menu_name = $ARGV[4];
$grub_file = $ARGV[5];
$grub_version = $ARGV[6];
$tpm_version = $ARGV[7];

open(FH, $grub_file);
open(OUT, ">>$output_file");


$isTboot = 0;
$isSameKernel = 0;

$flag = 0;
$buffer = "";

if ( $grub_version == 2 or $grub_version == 1 )
{
while(<FH>) {
	chomp;
	if($_ =~ /menuentry '/) {
		$flag = 1;
		$_ =~ s/menuentry '/menuentry '$menu_name /;
		$buffer = $_."\n";
	}
	elsif($flag == 1) {
		if($_ ne '}') {
			if ($_ =~ /tboot\.gz/ ) {
				$isTboot = 1;
				$_ .= " measure_nv=true";
				if ($tpm_version == "2.0") {
					$_ .= " extpol=embedded";
				}
				$buffer .= $_."\n";
	#		} elsif ( $_ =~ $kernel_version and !($_ =~ $kernel_arg ) )
			} elsif ( $_ =~ /$kernel_version/ and $_ =~ /vmlinu[xz]-/ and !($_ =~ $kernel_arg ) )
			{
				$isSameKernel = 1;
				$buffer .= $_ . " " . $kernel_arg . "\n";
			}
			else {
				$buffer .= $_."\n";
			}
		} else {
			$buffer .= "}\n";
			if ($isTboot == 1 and $isSameKernel == 1 )
			{
				$buffer =~ s/\/initr\S+$kernel_version\S*/\/$ARGV[2]/g;
				print OUT $buffer;
				exit 0;
			}
			else
			{
				$buffer = "";
				$flag = 0;
				$isTboot = 0;
				$isSameKernel = 0;
			}
		}	
	}
}
}
elsif ( $grub_version == 0 )
{
	while(<FH>) {
		
        	chomp;
		if( $flag == 0 and $buffer == "" )
		{
			if ($_ =~ /title /)
			{
				$_ =~ s/title /title $menu_name /;
				$buffer = $_."\n";
				$flag = 1;
			}
		}
		elsif ( $flag == 1 )
		{
			if ( $_ =~ /\s*kernel /)
			{
				if ( $_ =~ /tboot\.gz/ )
				{
					$buffer .= $_."\n";
				}
				elsif ( $_ =~ /$kernel_version/ and $_ =~ /vmlinu[xz]/)
				{
					$buffer .= "\tkernel /boot/tboot.gz logging=serial,vga,memory measure_nv=true\n";
					$_ =~ s/kernel/module/;
					$buffer .= $_. " " . $kernel_arg. "\n";
					$isSameKernel = 1;
				}
				$isTboot = 1;
			}
			elsif ( $_ =~ /$kernel_version/ and $_ =~ /vmlinu[xz]/ )
			{
				$buffer .= $_. " " . $kernel_arg. "\n";
				$isSameKernel = 1;
			}
			elsif( $_ =~ /title / )
			{
				if( $isTboot == 1 and $isSameKernel == 1 ) {
					last;
				}
				else {
					$_ =~ s/title /title $menu_name /;
	                                $buffer = $_."\n";
					$flag = 1;
					$isTboot = 0;
					$isSameKernel = 0;
				}
			}
			elsif( $_ =~ /\s*initrd / )
			{
				$_ =~ s/initrd /module /;
				$buffer .= $_."\n";
			}
			else {
				$buffer .= $_."\n";
			}
		}
	}
}
if ( $flag == 1 and $isTboot == 1 and $isSameKernel == 1 ) {
	$buffer =~ s/\/initr\S+$kernel_version\S*/\/$ARGV[2]/g;
        print OUT $buffer;
        exit 0;	
}
exit 1;
