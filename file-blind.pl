#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EPERM :POSIX);
use POSIX ":sys_wait_h";
use POSIX qw/SIGSTOP SIGTERM SIGCONT  WUNTRACED mkfifo/;
use Data::Dumper;
use File::Temp qw/tempfile/;
use Fcntl qw/F_SETFD F_GETFD/;
use English;

eval {
	my $ret = main (\@ARGV);
	exit ($ret);

} or do {
	my $err = $@;

	return unless $err;

	print "$err";
	exit (1);
};

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

	my @calls = ();

	my $spid = run_freezed ($argv);

	my (undef, $pipepath) = tempfile ('XXXXXXX', OPEN => 0);
	mkfifo ($pipepath, 0700);
	my $arel = AutoRel->new ($pipepath);
	
	# run in background with named pipe on the output
	system ("/usr/bin/stap -F -m blindmonitor -o $pipepath ./syscall-monitor.stp");
	open my $stap, '<', $pipepath;
	unlink ($pipepath);
	my $read = <$stap>;
	# proc interface is initialized
	if ( $read !~ /^STARTED/ ) {
		die "Stap not started.";
	}

	proc_write ("/proc/systemtap/blindmonitor/pids", $spid);
	async_unfreeze_proc ($spid);

	while ( my $line = <$stap> ) {
		my @call = split_line ($line);
		if ( !@call ) {
			next;
		}
		$call[1] = unescape ($call[1]);
		push (@calls, \@call) unless is_white_listed (\@call);
	}
	waitpid ($spid, 0);
	close $stap;
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
		$EGID = 20787;
		$EUID = 20787;
		exec (@$argv);
		exit (0);
	} elsif ( $pid > 0 ) {
		waitpid ($pid, WUNTRACED);
		return $pid;
	}
}

sub async_unfreeze_proc {
	my ($pid) = @_;
	kill SIGCONT, $pid;
}

sub unfreeze_proc {
	my ($pid) = @_;

	async_unfreeze_proc ($pid);
	waitpid ($pid, 0);
	return $?;
}

sub proc_write {
	my ($file, $value) = @_;

	open my $proc, '>', $file or die "Can't open $file";
	syswrite ($proc, $value) or die "Can't write value to file $file";
	close $proc;
}

sub blind_files_impl ($$) {
	my ($call, $argv) = @_;

	my $spid = run_freezed ($argv);

	proc_write ("/proc/systemtap/blinder/pids", $spid);
	proc_write ("/proc/systemtap/blinder/syscall", $call->[0]);
	proc_write ("/proc/systemtap/blinder/count", 0);
	proc_write ("/proc/systemtap/blinder/blocked_files", $call->[1]);

	my $status = unfreeze_proc ($spid);
	print "Child exited witch status: " . ($? >> 8) . " which is ";
	if ( $status != 0 ) {
		print "ERROR!";
		print "\nChild received " . ($status & 127) . " signal.\n";
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

package AutoRel;
use strict;
use warnings;
sub new {
	my ($class, $fd) = @_;
	my $this = {
		fd => $fd
	};
	bless $this, $class;
	return $this;
}

sub DESTROY {
	my ($this) = @_;
	close ($this->{fd}) if ($this->{fd});
}
