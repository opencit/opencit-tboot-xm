#!/usr/bin/perl

print $ARGV[0];   # output file 
print $ARGV[1];	  # kernel name
print $ARGV[2];   # initrd name
print $ARGV[3];	  # kernel arg
print $ARGV[4];	  # Menuentry name prefix
open(FH, "/boot/grub/grub.cfg");
open(OUT, ">>$ARGV[0]");

$isTboot = 0;
$isSameKernel = 0;

$flag = 0;
$buffer = "";

while(<FH>) {
	chomp;
	if($_ =~ /menuentry '/) {
		$flag = 1;
		$_ =~ s/menuentry '/menuentry '$ARGV[4] /;
		$buffer = $_."\n";
	}
	elsif($flag == 1) {
		if($_ ne '}') {
			if ($_ =~ /tboot\.gz/ ) {
				$isTboot = 1;
				$buffer .= $_ . "\n";
	#		} elsif ( $_ =~ $ARGV[1] and !($_ =~ $ARGV[3] ) )
			} elsif ( $_ =~ /$ARGV[1]/ and $_ =~ /vmlinu[xz]-/ and !($_ =~ $ARGV[3] ) )
			{
				$isSameKernel = 1;
				$buffer .= $_ . " " . $ARGV[3] . "\n";
			}
			else {
				$buffer .= $_."\n";
			}
		} else {
			$buffer .= "}\n";
			if ($isTboot == 1 and $isSameKernel == 1 )
			{ 
				$buffer =~ s/\/initr\S+$ARGV[1]\S*/\/$ARGV[2]/g;
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
exit 1;
