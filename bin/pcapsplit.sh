#! /usr/bin/env bash
# A wrapper of tcpdump to split a large trace into multiple small subtraces, supporting to processe a single pcap file and all files under a folder.
# By chenxm, Version 0.1
# 2012-11
function printinfo(){
	echo "Usage: $0 [-dD] [-s size(MB)] name"
	echo "	-d	The option indicates a folder provided"
	echo "	-D	Remove the original files or not"
	echo "	-s	Bin size to split files. The default is 64 MB corresponding to the default file piece in Hadoop"
	echo "	name	The file/folder name of pcap files"
}

if [ $# -lt 1 ]; then
	printinfo && exit 1;
fi

# Parsing options
isfolder=0
binsize=64
ifremove=0
while getopts dDs: o
do
	case "$o" in
		d)	isfolder=1;;
		D)	ifremove=1;;
		s)	binsize="$OPTARG";;
		[?])	printinfo; exit 1;;
	esac
done

shift $(($OPTIND-1)) && input="$@"
if [ -z $input ]; then
	printinfo && exit 1;
fi

# Processing file(s)
SUFIX="split"
output="$SUFIX"
if [ "$isfolder" -eq 1 ]; then
	if [ -d "$input" ]; then
		for filename in `ls $input`
		do
			fullname="$input/$filename"
			output="$fullname.$SUFIX"
			tcpdump -r "$input/$filename" -C "$binsize" -w $output
			if [ "$ifremove" -eq 1 ]; then
				echo "Removing $fullname"
				rm -f "$fullname"
			fi
		done
		exit 0;
	else
		echo "Option -d dose not match a folder"
		printinfo; exit 1;
	fi
else
	if [ -f "$input" ]; then
		# Processing single file
		output="$input.$SUFIX"
		tcpdump -r "$input" -C "$binsize" -w $output
		if [ "$ifremove" -eq 1 ]; then
			echo "Removing $input"
			rm -f "$input"
		fi
		exit 0;
	else
		echo "File not found."
		printinfo; exit 1;
	fi
fi

exit 0;