#!/usr/bin/perl

use strict;
use warnings;
use File::Basename;
use lib dirname($0);
use Devel::Plumber;
use Getopt::Long qw(:config no_ignore_case bundling);

my $binfile;
my $corefile;
my $pid;
my $verbose = 0;
my $progress = 0;
my $dodump = 0;

sub usage
{
    print STDERR <<EOF;
Usage: dumpit.pl [options] bin-file core-file
       dumpit.pl [options] bin-file pid
options are:
    --verbose	  be more verbose
    --progress    give a progress report
EOF
    exit 1;
}

sub parse_arguments
{
    GetOptions(
	'verbose+' => \$verbose,
	'progress' => \$progress,
	'dump-blocks' => \$dodump,
    ) or usage;

    $binfile = shift @ARGV || usage;
    die "No such binary file: $binfile"
	unless -f $binfile;

    $corefile = shift @ARGV || usage;
    if ($corefile =~ m/^\d+$/)
    {
	$pid = $corefile;
	$corefile = undef;
    }
    else
    {
	die "No such core file: $corefile"
	    unless -f $corefile;
    }
    usage if scalar(@ARGV);
}

parse_arguments();
# print "binfile=$binfile\n";
# print "corefile=$corefile\n" if defined $corefile;
# print "pid=$pid\n" if defined $pid;
# print "verbose=$verbose\n";
# print "progress=$progress\n";
# exit 0;

my $plumber = new Devel::Plumber(binfile => $binfile,
				 corefile => $corefile,
				 pid => $pid,
				 progress => $progress,
				 verbose => $verbose);

$plumber->find_leaks();
if ($dodump)
{
    $plumber->dump_blocks();
}
else
{
    $plumber->report_leaks();
}

