#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EPERM :POSIX);
use POSIX qw/SIGSTOP SIGTERM SIGCONT/;
use Data::Dumper;
use File::Temp;
use Fcntl qw/F_SETFD F_GETFD/;
use English;
use POSIX ":sys_wait_h";

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
	fcntl ($tmp, F_SETFD, 0);

	my $fn = fileno ($tmp);
	my $output = "/dev/fd/$fn";

	my $spid = run_freezed ($argv);

 	system ("/usr/bin/stap", "-F", "-m", "blindmonitor", "-w", "./syscall-monitor.stp", "-o", $output);

	open my $proc_pids, '>', "/proc/systemtap/blindmonitor/pids";
	print $proc_pids $spid;
	close $proc_pids;

	my $status = unfreeze_proc ($spid);

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
	system "cat /dev/fd/$fn";
	close $tmp;


	system ("killall stapio");
	return @calls;
}

sub run_injector_probe {
	system ("stap -F -m blinder -g -w ./syscall-injector.stp 2>/dev/null");
}

sub run_freezed ($) {
	my ($argv) = @_;

	my $pid = fork ();
	if ( $pid == -1 ) {
		die "Can't run process in freeze state!";
	} elsif ( $pid == 0 ) {
		kill SIGSTOP, $$;
		exec (@$argv);
		exit (0);
	} elsif ( $pid > 0 ) {
		return $pid;
	}
}

sub unfreeze_proc {
	my ($pid) = @_;

	kill SIGCONT, $pid;
	waitpid ($pid, 0);
	return $?;
}

sub blind_files_impl ($$) {
	my ($call, $argv) = @_;

	my $spid = run_freezed ($argv);

	open my $proc_pids, '>', "/proc/systemtap/blinder/pids";
	print $proc_pids $spid;
	close $proc_pids;

	open my $proc_syscall, '>', "/proc/systemtap/blinder/syscall";
	print $proc_syscall $call->[0];
	close $proc_syscall;

	open my $proc_count, '>', "/proc/systemtap/blinder/count";
	print $proc_count 0;
	close $proc_count;

	open my $proc_blocked, '>', "/proc/systemtap/blinder/blocked_files";
	print $proc_blocked $call->[1];
	close $proc_blocked;

	my $status = unfreeze_proc ($spid);
	print "Child exited witch status: $? which is ";
	if ( $status != 0 ) {
		print "ERROR!";
		print "\nChild received " . ($status & 127) . " signal.\n";
		sleep (10);
	} else {
		print "Ok";
	}
	print "\n";
}

sub blind_files ($$) {
	my ($calls, $argv) = @_;

	run_injector_probe ();
	foreach my $call (@$calls) {
		print "Blinding $call->[0] ($call->[1])\n";
		blind_files_impl ($call, $argv);
	}

	system ("staprun -d blinder");
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
