use File::Basename;
use File::Copy;
#input File containing GRUB entry
$input_file=$ARGV[0];
print $input_file."\n";

#grub output File
$output_file=$ARGV[1];
print $output_file."\n";

#GRUB Version
$grub_version=$ARGV[2];
print $grub_version."\n";

#Menu entry Name
$menu_name=$ARGV[3];
print $menu_name."\n";

$flag=0;

open(FH, "<$output_file") or die "Couldn't open $output_file ,$!";

$temp_file=basename($output_file);
$temp_file="/tmp/" . $temp_file;
open(OUT, ">$temp_file") or die "Couldn't open $temp_file ,$!";

if ( $grub_version == 2 or $grub_version == 1 ) {
	while(<FH>) {
		if ( $_ =~ /menuentry '$menu_name/ ) {
			$flag=1;
		}
		elsif ( $flag==1 ) {
			chomp;
			if ( $_ eq "}" )
			{
				$flag = 0;
			}
		}
		else
		{
			print OUT $_;
		}
	}
}
elsif ( $grub_version == 0 ) {
	while(<FH>) {
		if( $_ =~ /title $menu_name/ ) {
			$flag=1;
		}
		elsif( $flag==1 ) {
			
			if ( $_ =~ /title / ) {
				$flag = 0;
				print OUT $_;
			}
		}
		else {
			print OUT $_;
		}
	}
}
else
{
	print "Grub version not supported\nExiting...";
	exit 1;
}
close OUT or die "Couldn't close $temp_file ,$!";
close FH or die "Couldn't close $output_file ,$!";
open(FH, "<$input_file") or die "Couldn't open $input_file ,$!";
open(OUT, ">>$temp_file") or die "Couldn't open $temp_file ,$!";
while(<FH>)
{
	print OUT $_;
}
close FH or die "Couldn't close $input_file ,$!";
close OUT or die "Couldn't close $temp_file ,$!";
$base_out_file="/tmp/".basename($output_file);
move ($output_file,$base_out_file.".old") or die "Couldn't move the original file to temp";
move ($temp_file,$output_file) or die "Couldn't replace the old file with new file";
chmod 0755,$output_file;
