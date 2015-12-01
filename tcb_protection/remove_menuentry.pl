#!/usr/bin/perl
use File::Basename;
use File::Copy;

$GRUB_VERSION=$ARGV[0];
$GRUB_FILE=$ARGV[1];
$menu_name=$ARGV[2];
$flag=0;

open(FH, "<$GRUB_FILE") or die "Couldn't open $GRUB_FILE ,$!";

$temp_file=basename($GRUB_FILE);
$temp_file="/tmp/" . $temp_file;

open(OUT, ">$temp_file") or die "Couldn't open $temp_file ,$!";


if( $GRUB_VERSION == 2 or $GRUB_VERSION == 1 )
{
	while( <FH> ) 
	{
		if ( $_ =~ /menuentry '$menu_name/ ) {
			$flag=1;
		}
		elsif ( $flag == 1) {
			chomp;
			if ( $_ eq "}" )
			{
				$flag=0;
			}
		}
		else {
			print OUT $_;
		}
	}
}
elsif  ( $GRUB_VERSION == 0 )
{
	while( <FH> )
	{
		if ( $_ =~ /title $menu_name/ ) {
			$flag=1;
		}
		elsif ( $flag == 1 ) {
			if ( $_ =~  /title / ) {
				print OUT $_;
				$flag=0;
			}
		}
		else {
			print OUT $_;
		}
	}
}
else
{
	print "GRUB version not supported\nExiting...";
	exit 1;
}

close OUT or die "Couldn't close $temp_file ,$!";
close FH or die "Couldn't close $GRUB_FILE ,$!";
move ($GRUB_FILE, "/tmp/" . basename($GRUB_FILE) . ".old") or die "Couldn't move the original file to tmp";
move ($temp_file, $GRUB_FILE) or die "Couldn't move the new GRUB file from tmp to its destination";
chmod 0755,$GRUB_FILE;
