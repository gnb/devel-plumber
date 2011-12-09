#!/usr/bin/perl

use strict;
use warnings;
use threads;
use IO::File;
use Devel::GDB;
use Tree::Interval;
use Getopt::Long qw(:config no_ignore_case bundling);

my $binfile;
my $corefile;
my $pid;
my $verbose = 0;
my $progress = 0;
my $blocks = Tree::Interval->new();
my $sections = Tree::Interval->new();

# states
my $FREE = 0;
my $LEAKED = 1;
my $MAYBE = 2;
my $REACHED = 3;
my @state_names = qw(free LEAKED MAYBE_LEAKED reached);

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
	'progress+' => \$progress,
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

my $gdb = new Devel::GDB( '-create-expect' => 1,
                          '-params' => [ '-q' ] );
my $e = $gdb->get_expect_obj;

$gdb->send_cmd("file $binfile");
$gdb->send_cmd("core-file $corefile")
    if defined $corefile;
$gdb->send_cmd("attach $pid")
    if defined $pid;

sub get_hex_expr
{
    my ($expr) = @_;
    my $line = $gdb->get("output (void *)($expr)") || return;
    $line =~ s/\n//g;
    $line =~ s/^.*\)\s*//;
    $line =~ s/\s//g;
    return 0 + oct($line);
}

sub get_symbol
{
    my ($expr) = @_;
    my $line = $gdb->get("info sym ($expr)") || return;

    # _nss_nis_getgrgid_r + 1 in section .text
    # _nss_nis_getgrgid_r in section .text
    my ($sym, $off) = ($line =~ m/^\s*(\S*)\s*\+\s*(\d+)\s+in\s+section\s+(\S+)/);
    return ($sym, 0+$off)
	if (defined $off);
    ($sym) = ($line =~ m/^\s*(\S*)\s+in\s+section\s+(\S+)/);
    return ($sym, 0);
}

my $word_xletter;
my $word_mask;
my $word_fmt;
my $word_unpack;
my $word_pack;
my $word_size = get_hex_expr('sizeof (void *)');

if ($word_size == 4)
{
    $word_xletter = 'w';
    $word_mask = 0x3;
    $word_fmt = '0x%08x';
    $word_unpack = 'CCCC';
    $word_pack = 'L';
}
elsif ($word_size == 8)
{
    $word_size = 8;
    $word_xletter = 'g';
    $word_mask = 0x7;
    $word_fmt = '0x%016x';
    $word_unpack = 'CCCCCCCC';
    $word_pack = 'Q';
}
else
{
    die "Unknown word size: $word_size";
}

my $chunk_head_size = 2*$word_size;

sub get_hex_words
{
    my ($addr, $count) = @_;
    my $s = $gdb->get("x/" . $count . "x" . $word_xletter . " " . $addr);
    $s =~ s/0x[0-9a-f]+://g;
    $s =~ s/^\s+//;
    my @a = split(/\s+/, $s);
    map { $_ = oct($_); } @a;
    return @a;
}

sub load_sections
{
    #	0xb801c270 - 0xb802cea8 is .text in /usr/lib/libsasl2.so.2
    #	0x0804d3c0 - 0x080e28ec is .text
    #	`/home/gnb/software/plumber/cyrus/imapd', file type elf32-i386.
    my $binary;
    my $s = $gdb->get("info files");
    foreach (split(/\n/, $s))
    {
	chomp;

	my ($t) = m/`([^']+)',\s+file\s+type\s+/;
	if (defined $t)
	{
	    $binary = $t;
	    next;
	}

	my ($start, $end, $name, $image) =
	    m/\s*(0x[0-9a-f]+)\s*-\s*(0x[0-9a-f]+)\s+is\s+(\S+)(?:\s+in\s+(\S+))?/;
	if (defined $name)
	{
	    next if ($name =~ m/^load\d+$/);
	    $image ||= $binary;
	    $start = oct($start);
	    $end = oct($end) - 1;
	    printf "start=0x%x end=0x%x name=%s image=%s\n",
		    $start, $end, $name, $image if $verbose;
	    eval
	    {
		# sometimes gdb reports overlapping sections
		# but it doesn't seem to be for important ones
		# so just ignore it
		$sections->insert($start, $end, {
		    addr => $start,
		    size => $end - $start,
		    name => $name,
		    image => $image,
		});
	    };
	    next;
	}
    }
}
load_sections();

my $nprogress = 0;
sub progress
{
    if ($progress)
    {
	$nprogress++;
	if ($nprogress % 20 == 0)
	{
	    print STDERR '.';
	    STDERR->flush;
	}
    }
}

sub add_chunk
{
    my ($addr, $size, $state) = @_;
    $addr += $chunk_head_size;
    $size -= $chunk_head_size;
    my $end = $addr + $size - 1;

    progress();

    my $old = $blocks->find($addr);
    die "Duplicate block at $addr"
	if (defined $old &&
	    ($old->{addr} != $addr ||
	     $old->{size} != $size ||
	     $old->{state} != $FREE));
    return if ($old);
    $blocks->insert($addr,$end,
	{
	    mark_gen => 0,
	    addr => $addr,
	    size => $size,
	    state => $state,
	});
    printf "block 0x%x %d %s\n",
	$addr, $size, $state_names[$state] if $verbose;
}

sub make_root
{
    my ($addr, $size) = @_;
    return
	{
	    mark_gen => 0,
	    addr => $addr,
	    size => $size,
	    state => $REACHED,
	};
}

my $main_arena = get_hex_expr('&main_arena');
my $size_arena = get_hex_expr('sizeof main_arena');
my $top = get_hex_expr('main_arena.top');
my $max_addr = get_hex_expr('(unsigned long)main_arena.top + main_arena.top->size & ~0x7');
my $min_addr = get_hex_expr("$max_addr - main_arena.system_mem");

# printf "main_arena=0x%x\n", $main_arena;
# printf "size_arena=0x%x\n", $size_arena;
# printf "max_addr=0x%x\n", $max_addr;
# printf "min_addr=0x%x\n", $min_addr;
# exit 0;

sub chunksize
{
    my ($chunk) = @_;
    # The 0x7 here masks out the extra bits of info
    # stored in the chunk size, and is fixed for all
    # word sizes.
    return get_hex_expr("((struct malloc_chunk *)$chunk)->size") & ~0x7;
}

sub walk_freelist
{
    my ($chunk, $desc) = @_;
    my $n = 0;

    while ($chunk >= $min_addr && $chunk < $max_addr)
    {
	printf "free 0x%x %d\n", $chunk, chunksize($chunk) if $verbose;
	add_chunk($chunk, chunksize($chunk), $FREE)
	    if ($chunk != $top);
	$chunk = get_hex_expr("((struct malloc_chunk *)$chunk)->fd");
	$n++;
    }
    print "Found $n free blocks on freelist: $desc\n" if ($verbose && $n);
}

# print "Walking freelists\n";
for (my $i = 0 ; $i < 10 ; $i++)
{
#     my $chunk = get_hex_expr("main_arena.fastbinsY[$i]");
    my $chunk = get_hex_expr("main_arena.fastbins[$i]");
    walk_freelist($chunk, sprintf("fastbin %d", $i));
}

for (my $i = 0 ; $i < 254 ; $i+=2)
{
    my $chunk = get_hex_expr("main_arena.bins[$i]");
    walk_freelist($chunk, sprintf("bin %d", $i/2));
}

sub walk_chunks
{
    my $chunk;
    my $size;

    for ($chunk = $min_addr ;
         $chunk < $max_addr ;
	 $chunk += $size)
    {
	$size = chunksize($chunk);
	add_chunk($chunk, $size, $LEAKED)
	    if ($chunk != $top);
    }
}

my $mark_gen = 1;
sub mark_blocks
{
    my ($rootaddr, $rootsize) = @_;

    # We do a breadth-first traversal of blocks.
    #
    # Initialise the pending list a fake block representing
    # the root section.  It won't be entered into the global
    # data structure so it can't be accidentally found later.
    my @pending = ( make_root($rootaddr, $rootsize) );

    while (my $block = shift @pending)
    {
	printf "    block=0x%x\n", $block->{addr} if $verbose;

	# avoid loops
	next if $block->{mark_gen} == $mark_gen;
	$block->{mark_gen} = $mark_gen;

	# Hmm, this is a dangling pointer, we should
	# probably complain about it.
	next if $block->{state} == $FREE;

	# try to reach other blocks pointed to by
	# the contents of this block
	my @words = get_hex_words($block->{addr},
				  int($block->{size} / $word_size));
	foreach my $word (@words)
	{
	    progress();

	    my $ref = $blocks->find($word);
	    if (defined $ref)
	    {
		printf "    ref=0x%x\n", $ref->{addr} if $verbose;

		# mark the block reached
		my $state = ($word == $ref->{addr}) ? $block->{state} : $MAYBE;
		$ref->{state} = $state
		    if $state > $ref->{state};

		# push on the stack
		push (@pending, $ref)
	    }
	}
    }

    $mark_gen++;
}

my @asciify;

sub setup_asciify
{
    map { $asciify[$_] = " ." } (0..255);
    $asciify[0x0a] = "\\n";
    $asciify[0x0d] = "\\r";
    map { $asciify[$_] = sprintf(" %c", $_) } (0x20..0x7e);
}
setup_asciify();

sub asciify_word
{
    my ($word) = @_;
    my @bytes = unpack($word_unpack, pack($word_pack, $word));
    return join(' ', map { $asciify[$_]; } @bytes);
}

sub describe_word
{
    my ($word) = @_;

    my $block = $blocks->find($word);
    if ($block)
    {
	return sprintf("ptr to %s block of %d bytes",
		$state_names[$block->{state}],
		$block->{size})
	    if ($word == $block->{addr});
	return sprintf("ptr %d bytes into %s block of %d bytes at $word_fmt",
		($word - $block->{addr}),
		$state_names[$block->{state}],
		$block->{size},
		$block->{addr});
    }

    my $sec = $sections->find($word);
    if ($sec)
    {
	my ($sym, $off) = get_symbol($word);
	return sprintf("%s in section %s in %s",
		$sym,
		$sec->{name},
		$sec->{image})
	    if (defined $sym && $off == 0);
	return sprintf("%s+%d in section %s in %s",
		$sym, $off,
		$sec->{name},
		$sec->{image})
	    if (defined $sym && $off == 0);
	return sprintf("offset 0x%x into section %s in %s",
		($word - $sec->{addr}),
		$sec->{name},
		$sec->{image});
    }

    return undef;
}

sub hexdump
{
    my ($addr, $size, $prefix) = @_;
    my $off = 0;
    my @words = get_hex_words($addr, int($size / $word_size));
    foreach my $word (@words)
    {
	my $asciified = asciify_word($word);
	my $desc = describe_word($word);
	$desc = ($desc ? "\t// $desc" : "");
	printf "%s0x%04x: " . $word_fmt . " %s%s\n",
	    $prefix, $off, $word, $asciified, $desc;
	$off += $word_size;
    }
}

sub dump_leaks
{
    my @count = ( 0, 0, 0, 0 );
    my @size = ( 0, 0, 0, 0 );

    printf "==== LEAKS ====\n";
    foreach my $block ($blocks->values())
    {
	if ($block->{state} == $LEAKED || $block->{state} == $MAYBE)
	{
	    printf "%s %d bytes at $word_fmt\n",
		$state_names[$block->{state}],
		$block->{size},
		$block->{addr};
	    hexdump($block->{addr}, $block->{size}, "    ");
	}
	$count[$block->{state}] ++;
	$size[$block->{state}] += $block->{size};
    }
    printf "==== SUMMARY ====\n";
    foreach my $state ($FREE..$REACHED)
    {
	printf "%d bytes in %d blocks %s\n",
	    $size[$state],
	    $count[$state],
	    $state_names[$state];
    }
}

walk_chunks();

# my $data_start = get_hex_expr("&__data_start");
# my $data_end = get_hex_expr("&_edata");
# mark_blocks($data_start, $data_end-$data_start);
# 
# my $bss_start = get_hex_expr("&__bss_start");
# my $bss_end = get_hex_expr("&_end");
# mark_blocks($bss_start, $bss_end-$bss_start);

my %is_root =
(
    '.bss' => 1,
    '.data' => 1,
);

my @root_sections = grep { $is_root{$_->{name}} } $sections->values();
foreach my $sec (@root_sections)
{
    printf "Marking blocks for section %s in %s\n",
	$sec->{name}, $sec->{image} if $verbose;
    mark_blocks($sec->{addr}, $sec->{size});
}

print STDERR "\n" if $progress;
dump_leaks();

$gdb->end;
$e->slave->close;
$e->expect(undef);

