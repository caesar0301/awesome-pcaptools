#!/usr/bin/perl 

use Shell qw(mkdir echo cat);
use FileHandle;

# This script is used to create the flow object (filelist) and the 
# output directory which contains reassembled flows. You simply provided 
# it with the dump files, and tcpdemux (Nprobe - Cambridge) will reassemble 
# the flows. 
#
# Author: Kaysar Abdin (NRL)

my $path_demux = "demuxer";
my $file = $ARGV[0];
mkdir("out");
# invoke the demuxer with the dumpfilelist
print STDERR "Processing dump files\n";
my $pipe_demux = open PIPE_DEMUX, cat "$file | $path_demux"; 

#open senses
unless (open(SENSES, "senses")) {
	die ("Cannot open input file: senses\n");
}

unless (open(FILELIST, ">filelist")){
	die("Cannot open output file: filelist\n");
}

print STDERR "Creating the Filelist object\n";

$line = <SENSES>;
while($line ne ""){

	my @templist = split(/ /, $line);
	
	print FILELIST ("out/$templist[0]\n");
	$line = <SENSES>;
}
print "FLOWCREATOR COMPLETED!\n";
