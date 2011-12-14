#!/usr/bin/perl

use strict;
use warnings;
use IO::File;
use lib 'lib';
use Test::Unit::TestRunner;

my $testrunner = Test::Unit::TestRunner->new();
$testrunner->start('Tree::Interval::Test');

my @cmds = (
    "make -C test run",
);

foreach my $cmd (@cmds)
{
    print "$cmd\n";
    STDOUT->flush;
    my $res = system($cmd);
    die "Failed running: $cmd" unless defined $res && $res == 0;
}
