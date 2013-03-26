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
		return undef;
	}
	return undef if ( $fields[0] ne "PROBE" );
	# drop PROBE field
	shift @fields;

	return @fields;
}

sub main {
	my ($argc) = @_;

	open my $stap, "stap ./syscall-monitor.stp -c @$argc|" or die "Can't fork! $!";

	# get list of called syscalls, path names, return codes
	my @calls = ();
	while ( my $line = <$stap> ) {
		my @call = split_line ($line);
		if ( ! @call ) {
			print STDERR "Wrong line! $line";
			next;
		}

		push @calls, \@call;
	}
	close $stap or die "Failed! I can't run program as param!";

	return 0;
}
