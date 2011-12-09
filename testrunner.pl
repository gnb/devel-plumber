#!/usr/bin/perl

use strict;
use warnings;
use Test::Unit::TestRunner;

my $testrunner = Test::Unit::TestRunner->new();
$testrunner->start('Tree::Interval::Test');
