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
	$line =~ s/(?<!\\)'([\W|\w])(?<!\\)'/$1/g;
	$line =~ s/^'//g;
	$line =~ s/'$//g;
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

sub unescape {
	my ($s) = @_;

	$s =~ s/\\,/,/g;
	$s =~ s/\\'/'/g;
	return $s;
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
		$call[1] = unescape ($call[1]);
		push (@calls, \@call) unless is_white_listed (\@call);
	}
	close $stap or die "FAIL! I can't execute program!";

	return @calls;
}

sub blind_files_impl {
	my ($call) = @_;
}

sub blind_files {
	my ($calls) = @_;

	foreach my $call (@$calls) {
		blind_files_impl ($call);
	}
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
