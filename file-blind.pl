#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EPERM :POSIX);
use Data::Dumper;

my $ret = main ();
exit ($ret);

sub main {
	open my $stap, "stap ./syscall-monitor.stp -c ./test|" or die "Can't fork! $!";

	my @calls = ();
	while ( my $line = <$stap> ) {
		next if ( $line !~ m/^'PROBE',/ );

		tie my %call, 'CallsHash', $line;

		if ( ! %call ) {
			print STDERR "Wrong line! $line";
			next;
		}

		push @calls, \%call;
	}
	close $stap or die "Failed with: $!";

	return 0;
}

package CallsHash;
use strict;
use warnings;
use base 'Tie::Hash';

sub TIEHASH {
	my ($class, $line) = @_;

	# black magic...
	chomp $line;
	$line =~ s/([^\\]?)'/$1/g;
	my @fields = split (/(?<!\\),/x, $line);

	return undef if ( $fields[0] ne "PROBE" );

	my $keys_map = {
		probe 		=> 0,
		syscall		=> 1,
		path	 	=> 2,
		ret_code	=> 3,
	};
	my $map_size = keys %$keys_map;

	if (scalar (@fields) < $map_size) {
		return undef;
	}

	my $this = {
		line => $line,
		fields => \@fields,
		keys_map => $keys_map,
		map_size => $map_size,
	};

	bless $this, $class;
}

sub STORE {
	print STDERR "Read only values!";
	return undef;
}

# boilerplate
sub FIRSTKEY {
	my ($this) = @_;
	my $h = keys %{$this->{keys_map}};
	return each %{$this->{keys_map}};
}

sub NEXTKEY {
	my ($this, $lastkey) = @_;
	return each %{$this->{keys_map}};
}

sub FETCH {
	my ($this, $key) = @_;
	my $fid = $this->{keys_map}->{lc $key};
	return $this->{fields}[$fid];
}
1;

