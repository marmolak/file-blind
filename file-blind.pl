#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EPERM :POSIX);
use Data::Dumper;

my $ret = main (\@ARGV);
exit ($ret);

sub split_line {
	my ($line) = @_;

	chomp $line;
	$line =~ s/([^\\]?)'/$1/g;
	my @fields = split (/(?<!\\),/x, $line);
	if (scalar (@fields) < 4) {
		return ();
	}
	return () if ( $fields[0] ne "PROBE" );
	# drop PROBE field
	shift @fields;

	return @fields;
}

sub get_file_list {
	my ($argv) = @_;

	open my $stap, "stap ./syscall-monitor.stp -c \"@$argv\"|" or die "Can't fork! $!";

	# get list of called syscalls, path names, return codes
	my @calls = ();
	while ( my $line = <$stap> ) {
		my @call = split_line ($line);
		if ( !@call ) {
			# is program line? just print line
			print $line;
			next;
		}
		push @calls, \@call;
	}
	close $stap or die "FAIL! I can't execute program!";

	return @calls;
}

sub main {
	my ($argv) = @_;

	my @calls = get_file_list ($argv);

	if ( ! @calls ) {
		print "Nothing to examine.\n";
		return 0;
	}

	return 0;
}
