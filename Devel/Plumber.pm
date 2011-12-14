package Devel::Plumber;

use strict;
use warnings;
no warnings 'portable';  # Support for 64-bit ints required
use vars qw($VERSION);
$VERSION = '0.2';
use threads;
use IO::File;
use Devel::GDB;
use Tree::Interval;

# states of a block
my $FREE = 0;
my $LEAKED = 1;
my $MAYBE = 2;
my $REACHED = 3;
my @state_names = qw(free LEAKED MAYBE_LEAKED reached);

sub new
{
    my ($class, %params) = @_;
    my $self =
    {
	verbose => 0,
	progress => 0,
	blocks => Tree::Interval->new(),
	sections => Tree::Interval->new(),
	nprogress => 0,
	gdb => undef,
	expect => undef,
    };
    bless $self, $class;
    $self->setup(%params) if scalar(%params);
    return $self;
}

sub close
{
    my ($self) = @_;

    if ($self->{gdb})
    {
	$self->{gdb}->end;
	$self->{expect}->slave->close;
	$self->{expect}->expect(undef);
	$self->{expect} = undef;
	$self->{gdb} = undef;
    }
}

sub DESTROY
{
    my ($self) = @_;
    $self->close();
}

sub setup
{
    my ($self, %params) = @_;
    my $binfile = delete $params{binfile};
    my $corefile = delete $params{corefile};
    my $pid = delete $params{pid};
    my $progress = delete $params{progress} || 0;
    my $verbose = delete $params{verbose} || 0;

    die "Unexpected parameters: " . join(" ", keys %params)
	if scalar(%params);

    $self->{progress} = $progress;
    $self->{verbose} = $verbose;
    $self->_setup_gdb($binfile, $corefile, $pid);
    $self->_setup_platform();
    $self->_setup_sections();

    return 1;
}

sub _setup_gdb
{
    my ($self, $binfile, $corefile, $pid) = @_;

    return 1 if defined $self->{gdb};
    die "Required parameter binfile missing"
	unless defined $binfile;
    die "Either a corefile or a pid parameter is required"
	unless (defined $corefile || defined $pid);

    my $gdb = new Devel::GDB( '-create-expect' => 1,
			      '-params' => [ '-q' ] );
    die "Faield to create Devel::GDB object"
	unless $gdb;

    $gdb->send_cmd("file $binfile");
    $gdb->send_cmd("core-file $corefile")
	if defined $corefile;
    $gdb->send_cmd("attach $pid")
	if defined $pid;

    $self->{gdb} = $gdb;
    $self->{expect} = $gdb->get_expect_obj();
}

sub _setup_platform
{
    my ($self) = @_;

    my $word_size = $self->_expr('sizeof (void *)');
    my $plat;

    if ($word_size == 4)
    {
	$plat =
	{
	    word_size => 4,
	    word_xletter => 'w',
	    word_mask => 0x3,
	    word_fmt => '0x%08x',
	    word_unpack => 'CCCC',
	    word_pack => 'L',
	    chunk_head_size => 2*$word_size,
	};
    }
    elsif ($word_size == 8)
    {
	$plat =
	{
	    word_size => 8,
	    word_xletter => 'g',
	    word_mask => 0x7,
	    word_fmt => '0x%016x',
	    word_unpack => 'CCCCCCCC',
	    word_pack => 'Q',
	    chunk_head_size => 2*$word_size,
	};
    }
    else
    {
	die "Unknown word size: $word_size";
    }

    $self->{platform} = $plat;
}

sub _vmsg
{
    my ($self, $fmt, @args) = @_;

    return unless $self->{verbose};
    print STDERR "plumber: " . sprintf($fmt, @args) . "\n";
    STDERR->flush;
}

sub _progress_begin
{
    my ($self) = @_;
    return unless $self->{progress};
    print STDERR "\n";
    STDERR->flush;
}

sub _progress_tick
{
    my ($self) = @_;

    return unless $self->{progress};
    $self->{nprogress}++;
    if ($self->{nprogress} % 20 == 0)
    {
	print STDERR '.';
	STDERR->flush;
    }
}

sub _progress_end
{
    my ($self) = @_;
    return unless $self->{progress};
    print STDERR "\n";
    STDERR->flush;
}

sub _expr
{
    my ($self, $expr) = @_;
    my $line = $self->{gdb}->get("output (void *)($expr)") || return;
    $line =~ s/\n//g;
    $line =~ s/^.*\)\s*//;
    $line =~ s/\s//g;
    my $r = 0 + oct($line);
    print STDERR "==> _expr($expr) = $r\n" if ($self->{verbose} > 1);
    return $r;
}

sub _symbol
{
    my ($self, $expr) = @_;
    my $line = $self->{gdb}->get("info sym ($expr)") || return;

    # _nss_nis_getgrgid_r + 1 in section .text
    # _nss_nis_getgrgid_r in section .text
    my ($sym, $off) = ($line =~ m/^\s*(\S*)\s*\+\s*(\d+)\s+in\s+section\s+(\S+)/);
    return ($sym, 0+$off)
	if (defined $off);
    ($sym) = ($line =~ m/^\s*(\S*)\s+in\s+section\s+(\S+)/);
    return ($sym, 0);
}

sub _words
{
    my ($self, $addr, $count) = @_;
    my $plat = $self->{platform};
    my $s = $self->{gdb}->get("x/" . $count . "x" .
			      $plat->{word_xletter} .
			      " " . $addr);
    $s =~ s/0x[0-9a-f]+://g;
    $s =~ s/^\s+//;
    my @a = split(/\s+/, $s);
    map { $_ = oct($_); } @a;
    return @a;
}

sub _setup_sections
{
    my ($self) = @_;

    #	0xb801c270 - 0xb802cea8 is .text in /usr/lib/libsasl2.so.2
    #	0x0804d3c0 - 0x080e28ec is .text
    #	`/home/gnb/software/plumber/cyrus/imapd', file type elf32-i386.
    my $binary;
    my $s = $self->{gdb}->get("info files");
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
	    $end = oct($end);
	    $self->_vmsg("start=0x%x end=0x%x name=%s image=%s",
			 $start, $end, $name, $image);
	    eval
	    {
		# sometimes gdb reports overlapping sections
		# but it doesn't seem to be for important ones
		# so just ignore it
		$self->{sections}->insert($start, $end-1, {
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

sub _chunk_size
{
    my ($self, $chunk) = @_;
    # The 0x7 here masks out the extra bits of info
    # stored in the chunk size, and is fixed for all
    # word sizes.
    return $self->_expr("((struct malloc_chunk *)$chunk)->size") & ~0x7;
}

sub _add_chunk
{
    my ($self, $addr, $size, $state) = @_;
    my $plat = $self->{platform};
    $addr += $plat->{chunk_head_size};
    $size -= $plat->{chunk_head_size};
    my $end = $addr + $size - 1;

    $self->_progress_tick();

    my $old = $self->{blocks}->find($addr);
    die "Duplicate block at $addr"
	if (defined $old &&
	    ($old->{addr} != $addr ||
	     $old->{size} != $size ||
	     $old->{state} != $FREE));
    return if ($old);
    $self->{blocks}->insert($addr, $end,
	{
	    marked => 0,
	    addr => $addr,
	    size => $size,
	    state => $state,
	});
    $self->_vmsg("block 0x%x %d %s",
		 $addr, $size, $state_names[$state]);
}

sub _make_root
{
    my ($addr, $size) = @_;
    return
	{
	    marked => 0,
	    addr => $addr,
	    size => $size,
	    state => $REACHED,
	};
}

sub _make_arena
{
    my ($self, $addr) = @_;

    my $top = $self->_expr("((struct malloc_state *)$addr)->top");
    my $max_addr = $top + $self->_chunk_size($top);
    my $min_addr = $max_addr - $self->_expr("((struct malloc_state *)$addr)->system_mem");

    # printf "top=0x%x\n", $top;
    # printf "min_addr=0x%x\n", $min_addr;
    # printf "max_addr=0x%x\n", $max_addr;
    # exit 0;

    my $arena =
    {
	addr => $addr,
	top => $top,
	max_addr => $max_addr,
	min_addr => $min_addr,
    };
    return $arena;
}

sub _walk_freelist
{
    my ($self, $arena, $chunk, $desc) = @_;
    my $n = 0;

    while ($chunk >= $arena->{min_addr} && $chunk < $arena->{max_addr})
    {
	$self->_vmsg("free 0x%x %d", $chunk, $self->_chunk_size($chunk));
	$self->_add_chunk($chunk, $self->_chunk_size($chunk), $FREE)
	    if ($chunk != $arena->{top});
	$chunk = $self->_expr("((struct malloc_chunk *)$chunk)->fd");
	$n++;
    }
    $self->_vmsg("Found $n free blocks on freelist: $desc") if ($n);
}

sub _walk_chunks
{
    my ($self, $arena) = @_;
    my $chunk;
    my $size;

    for ($chunk = $arena->{min_addr} ;
         $chunk < $arena->{max_addr} ;
	 $chunk += $size)
    {
	$size = $self->_chunk_size($chunk);
	$self->_add_chunk($chunk, $size, $LEAKED)
	    if ($chunk != $arena->{top});
    }
}

sub _walk_arena
{
    my ($self, $arena) = @_;

    $self->_vmsg("Arena $arena->{addr}");

    $self->_vmsg("Walking freelists");
    for (my $i = 0 ; $i < 10 ; $i++)
    {
	my $chunk = $self->_expr("((struct malloc_state *)$arena->{addr})->fastbinsY[$i]");
	# my $chunk = $self->_expr("($arena->{addr})->fastbins[$i]");
	$self->_walk_freelist($arena, $chunk, "fastbin $i");
    }

    for (my $i = 0 ; $i < 254 ; $i+=2)
    {
	my $chunk = $self->_expr("((struct malloc_state *)$arena->{addr})->bins[$i]");
	$self->_walk_freelist($arena, $chunk, "bin " . $i/2);
    }

    $self->_walk_chunks($arena);
}

sub _mark_blocks
{
    my ($self, $rootaddr, $rootsize) = @_;
    my $plat = $self->{platform};

    # We do a breadth-first traversal of blocks.
    #
    # Initialise the pending list a fake block representing
    # the root section.  It won't be entered into the global
    # data structure so it can't be accidentally found later.
    my @pending = ( _make_root($rootaddr, $rootsize) );

    while (my $block = shift @pending)
    {
	$self->_vmsg("    block: 0x%x @ 0x%x", $block->{size}, $block->{addr});

	# avoid loops
	next if $block->{marked};
	$block->{marked} = 1;

	# Hmm, this is a dangling pointer, we should
	# probably complain about it.
	next if $block->{state} == $FREE;

	# try to reach other blocks pointed to by
	# the contents of this block
	my @words = $self->_words($block->{addr},
				  int($block->{size} / $plat->{word_size}));
	foreach my $word (@words)
	{
	    $self->_progress_tick();

	    my $ref = $self->{blocks}->find($word);
	    if (defined $ref)
	    {
		$self->_vmsg("    ref=0x%x", $ref->{addr});

		# mark the block reached
		my $state = ($word == $ref->{addr}) ? $block->{state} : $MAYBE;
		$ref->{state} = $state
		    if $state > $ref->{state};

		# push on the stack
		push (@pending, $ref)
	    }
	}
    }
}

sub find_leaks
{
    my ($self) = @_;

    $self->_progress_begin();

    $self->_walk_arena($self->_make_arena('&main_arena'));

    my %is_root = ( '.bss' => 1, '.data' => 1 );

    my @root_sections = grep { $is_root{$_->{name}} } $self->{sections}->values();
    foreach my $sec (@root_sections)
    {
	$self->_vmsg("Marking blocks for section %s in %s",
		     $sec->{name}, $sec->{image});
	$self->_mark_blocks($sec->{addr}, $sec->{size});
    }

    $self->_progress_end();
}

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

my @asciify;

sub _setup_asciify
{
    map { $asciify[$_] = " ." } (0..255);
    $asciify[0x0a] = "\\n";
    $asciify[0x0d] = "\\r";
    map { $asciify[$_] = sprintf(" %c", $_) } (0x20..0x7e);
}
_setup_asciify();

sub _asciify_word
{
    my ($self, $word) = @_;
    my $plat = $self->{platform};
    my @bytes = unpack($plat->{word_unpack}, pack($plat->{word_pack}, $word));
    return join(' ', map { $asciify[$_]; } @bytes);
}

sub _describe_word
{
    my ($self, $word) = @_;
    my $plat = $self->{platform};

    my $block = $self->{blocks}->find($word);
    if ($block)
    {
	return sprintf("ptr to %s block of %d bytes",
		$state_names[$block->{state}],
		$block->{size})
	    if ($word == $block->{addr});
	return sprintf("ptr %d bytes into %s block of %d bytes at $plat->{word_fmt}",
		($word - $block->{addr}),
		$state_names[$block->{state}],
		$block->{size},
		$block->{addr});
    }

    my $sec = $self->{sections}->find($word);
    if ($sec)
    {
	my ($sym, $off) = $self->_symbol($word);
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

sub _hexdump
{
    my ($self, $addr, $size, $prefix) = @_;
    my $plat = $self->{platform};
    my $off = 0;
    my @words = $self->_words($addr, int($size / $plat->{word_size}));
    foreach my $word (@words)
    {
	my $asciified = $self->_asciify_word($word);
	my $desc = $self->_describe_word($word);
	$desc = ($desc ? "\t// $desc" : "");
	printf "%s0x%04x: $plat->{word_fmt} %s%s\n",
	    $prefix, $off, $word, $asciified, $desc;
	$off += $plat->{word_size};
    }
}

sub report_leaks
{
    my ($self) = @_;
    my @count = ( 0, 0, 0, 0 );
    my @size = ( 0, 0, 0, 0 );
    my $plat = $self->{platform};

    printf "==== LEAKS ====\n";
    foreach my $block ($self->{blocks}->values())
    {
	if ($block->{state} == $LEAKED || $block->{state} == $MAYBE)
	{
	    printf "%s %d bytes at $plat->{word_fmt}\n",
		$state_names[$block->{state}],
		$block->{size},
		$block->{addr};
	    $self->_hexdump($block->{addr}, $block->{size}, "    ");
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

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

sub dump_blocks
{
    my ($self) = @_;

    foreach my $block ($self->{blocks}->values())
    {
	printf "0x%016x 0x%x %s\n",
		$block->{addr},
		$block->{size},
		$state_names[$block->{state}];
    }
}

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

sub get_leaks
{
    my ($self) = @_;

    my @leaks;
    foreach my $block ($self->{blocks}->values())
    {
	if ($block->{state} == $LEAKED || $block->{state} == $MAYBE)
	{
	    push(@leaks, {
		addr => $block->{addr},
		size => $block->{size},
		state => $block->{state},
	    });
	}
    }

    return \@leaks;
}

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
1;
