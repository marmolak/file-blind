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
	# output format:
	# syscall, pathname, return code

	return @fields;
}

sub is_white_listed {
	my ($call) = @_;

	my @white_list = qw( /proc/.* /sys/.* /lib/lib.* /lib64/lib.* /usr/lib/lib.* /usr/lib64/lib.* /usr/share/locale.* /tmp/.* /dev/.* /selinux/.* );

	foreach my $re (@white_list) {
		return 1 if ( $call->[1] =~ m/$re/ );
	}

	return 0;
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
		push (@calls, \@call) unless is_white_listed (\@call);
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
