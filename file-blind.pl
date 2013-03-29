#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EPERM :POSIX);
use Data::Dumper;
use File::Temp;
use Fcntl qw/F_SETFD F_GETFD/;

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

	my $tmp = File::Temp->new (UNLINK => 1);
	fcntl($tmp, F_SETFD, 0);

	my $fn = fileno ($tmp);
	my $output = "/dev/fd/$fn";
 	system ("/usr/bin/stap", "./syscall-monitor.stp", "-o", $output, "-c", "\"@$argv\"");

	my @calls = ();
	# get list of called syscalls, path names, return codes
	while ( (defined <$tmp>) && (my $line = <$tmp>) ) {
		my @call = split_line ($line);
		if ( !@call ) {
			next;
		}
		$call[1] = unescape ($call[1]);
		push (@calls, \@call) unless is_white_listed (\@call);
	}
	close $tmp;

	return @calls;
}

sub make_probe {
	my ($call) = @_;
	my ($syscall, $path, $ret) = @$call;

	open my $templ, '<', 'syscall-injector.tstp' or die "Can't open stp template file syscall-injector.tstp!";
	my $probe_stp = File::Temp->new (SUFFIX => '.stp', UNLINK => 1) or die "Can't create probe file!";

	while ( my $line = <$templ> ) {
		$line =~ s/%syscall%/$syscall/;
		$line =~ s/%pathname%/$path/;
		$line =~ s/%ret%/$ret/;
		my $errno = EPERM;
		$errno = -$errno;
		$line =~ s/%new_ret%/$errno/;

		my $param_name = "\$filename";
		if ( ($syscall eq "unlink") || ($syscall eq "creat") || ($syscall eq "statfs") ) {
			$param_name = "\$pathname";
		}
		$line =~ s/%paramname%/$param_name/g;

		print $probe_stp $line;
	}

	flush $probe_stp;
	return $probe_stp;
}

sub run_probe ($$) {
	my ($probe, $argv) = @_;

	my $probe_name = $probe->filename ();

	my $pid = fork ();
	if ( $pid == 0 ) {
		exec ("/usr/bin/stap", "-g", "$probe_name", "-c", @$argv);
		exit (0);
	} elsif ( $pid > 0 ) {
		waitpid ($pid, 0);
	} 
}

sub blind_files_impl ($$) {
	my ($call, $argv) = @_;

	print STDERR "\nBlinding call: $call->[0] (\"$call->[1]\") = $call->[2]\n";
	my $probe = make_probe ($call);
	print STDERR "\nCompiling and running PROBE...\n\n";
	run_probe ($probe, $argv);
}

sub blind_files ($$) {
	my ($calls, $argv) = @_;

	foreach my $call (@$calls) {
		blind_files_impl ($call, $argv);
	}
}

sub main {
	my ($argv) = @_;

	my @calls = get_file_list ($argv);

	if ( ! @calls ) {
		print "Nothing to examine.\n";
		return 0;
	}

	# remove duplicates
	my %seen = ();
	my @uniq_calls = grep { ! $seen{ join (',', @$_) }++ } @calls;

	blind_files (\@uniq_calls, $argv);

	return 0;
}
