package Tree::Interval::Node;

use strict;

sub new {
  my $type = shift;
  my $this = {};
  if (ref $type) {
    $this->{'parent'} = $type;
    $type = ref $type;
  }
  if (@_) {
    @$this{'low','high','val'} = @_;
  }
  return bless $this, $type;
}

sub DESTROY {
  if ($_[0]->{'left'}) { 
    (delete $_[0]->{'left'})->DESTROY;
  }
  if ($_[0]->{'right'}) {
    (delete $_[0]->{'right'})->DESTROY;
  }
  delete $_[0]->{'parent'};
}

sub low {
  my $this = shift;
  if (@_) {
    $this->{'low'} = shift;
  }
  $this->{'low'};
}

sub high {
  my $this = shift;
  if (@_) {
    $this->{'high'} = shift;
  }
  $this->{'high'};
}

sub val {
  my $this = shift;
  if (@_) {
    $this->{'val'} = shift;
  }
  $this->{'val'};
}

sub color {
  my $this = shift;
  if (@_) {
    $this->{'color'} = shift;
  }
  $this->{'color'};
}

sub left {
  my $this = shift;
  if (@_) {
    $this->{'left'} = shift;
  }
  $this->{'left'};
}

sub right {
  my $this = shift;
  if (@_) {
    $this->{'right'} = shift;
  }
  $this->{'right'};
}

sub parent {
  my $this = shift;
  if (@_) {
    $this->{'parent'} = shift;
  }
  $this->{'parent'};
}

sub successor {
  my $this = shift;
  if ($this->{'right'}) {
    return $this->{'right'}->min;
  }
  my $parent = $this->{'parent'};
  while ($parent && $this == $parent->{'right'}) {
    $this = $parent;
    $parent = $parent->{'parent'};
  }
  $parent;
}

sub min {
  my $this = shift;
  while ($this->{'left'}) {
    $this = $this->{'left'};
  }
  $this;
}

sub max {
  my $this = shift;
  while ($this->{'right'}) {
    $this = $this->{'right'};
  }
  $this;
}

1;
