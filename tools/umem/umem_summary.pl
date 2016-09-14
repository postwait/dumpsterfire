#!/usr/bin/perl
use strict;
use Data::Dumper;
use Getopt::Long;

sub usage() {
  print "$0 [-h] [-v] [-a <libname> [-a ....]] (-c <corefile> | -p <pid>)\n";
  print;
  print "\t-h\t\tthis usage message\n";
  print "\t-v\t\tverbose mode\n";
  print "\t-a <libname>\tcull stack calls with this libname in them\n";
  print "\t-c <corefile>\tthe corefile to analyze\n";
  print "\t-p <pid>\tthe active pid to analyze\n";
}
my %avoid_obj = (
	"libumem.so" => 1,
	"libc.so" => 1,
	"libstdc++.so" => 1,
	"ld.so" => 1,
);

my $verbose = 0;
my $help = 0;
my ($corefile, $pid);
GetOptions("v" => \$verbose,
           "h" => \$help,
           "c=s" => \$corefile,
           "a=s" => sub { $avoid_obj{$_[1]} = 1 },
           "p=i" => \$pid);

my $out;
if($help || $corefile && $pid || !($corefile || $pid)) {
  usage();
  exit(-1);
}
if($corefile) {
  open($out, "echo '::walk umem_cache | ::walk umem | ::whatis' | mdb $corefile |");
} else {
  open($out, "echo '::walk umem_cache | ::walk umem | ::whatis' | mdb -p $pid |");
}

my ($record, $cache, $begin_ml, $fptr, $seems_complete);
my @stack = ();
my $bystack = {};

while(<$out>){
  chomp;
#warn "READ <- $_";
  if(/^([0-9a-f]+) is allocated from (\S+):/) {
    flush();
    $record = $1;
    $cache = $2;
  }
  if(/^                 (\S*)$/) {
    if($1 eq '') {
      $seems_complete = 0;
      if($fptr) {
#warn "COMPLETE[$fptr]";
        push @stack, $fptr;
        $fptr = "";
      }
      $begin_ml = 1;
    }
    if($begin_ml && $seems_complete && $1 =~ /\+0x[0-9a-fA-F]+$/) { # two complete lines
#warn "COMPLETE[$fptr]";
      push @stack, $fptr;
      $fptr = "";
      $begin_ml = 0;
    }
    if($begin_ml) {
      my $fptrapp = "$fptr$1";
      my $fptr_complete = ($fptrapp =~ /\+0x[0-9a-fA-F]+$/);
#warn "ISCOMPLETE[$fptr_complete , $seems_complete] -> $fptrapp";
      if(!$seems_complete) {
        $fptr = "$fptrapp";
      }
      if($seems_complete && !$fptr_complete) { # Done
#warn "COMPLETE[$fptr]";
        push @stack, $fptr;
        $fptr = $1;
        if($fptr) { $begin_ml = 0; }
      }
      $seems_complete = $fptr_complete;
    } else {
#warn "COMPLETE[$1]";
      push @stack, $1;
    }
  }
}
flush();
summary();

sub filter_stack_call {
  $_ = shift;
  return 0 if(/^$/);
  if(/^([^`]+)`/) {
    (my $obj = $1) =~ s/\.so\.\d+(\.?).*$/.so/;
    return 0 if(exists($avoid_obj{$1}) || exists($avoid_obj{$obj}));
  }
  return 1;
}
sub flush {
  my @st = grep { filter_stack_call($_) } @stack;
  @stack = ();
  return if(scalar(@st) == 0);
  my $size = 0;
  if($cache =~ /_(\d+)$/) {
    $size = $1;
  } else {
    warn "$cache -> no size\n";
  }
  my $cs = join("$;", @st);
  $bystack->{$cs} ||= {};
  $bystack->{$cs}->{$size} ||= 0;
  $bystack->{$cs}->{$size}++;
  $bystack->{$cs}->{total} ||= 0;
  $bystack->{$cs}->{total} += $size;
}

sub guess_depth {
  my $depth = 0;
  my $look = 1;
  while($look) {
    my $cs = shift;
    last unless $cs;
    if($cs =~ /(eventer|mtev)_/) { $depth++; }
  }
  return $depth;
}
sub summary {
  print "SUMMARY:\n";
  my @allcs = sort { $bystack->{$a}->{total} <=> $bystack->{$b}->{total} } (keys %$bystack);
  foreach my $cs (@allcs) {
    my @st = split(/$;/, $cs);
    my $depth = guess_depth(@st);
    if($verbose) {
      print "------------------  STACK ---------------------\n";
      print join("\n", map { "\t$_" } @st);
      print "\n\n";
    }
    my $allocs = 0;
    print "                  bytes      allocs     bytes/alloc\n";
    foreach my $size (keys %{$bystack->{$cs}}) {
      next if ($size eq "total");
      if($verbose) {
        printf("              %9d     %7d         %7d\n", $bystack->{$cs}->{$size} * $size, $bystack->{$cs}->{$size}, $size);
        $allocs += $bystack->{$cs}->{$size};
        printf
      } else {
        printf("%9d %7d %6d %s\n", $bystack->{$cs}->{$size} * $size, $bystack->{$cs}->{$size}, $size, join(" <- ", @st[0..$depth]));
      }
    }
    printf("  Total:  %13d    %8d\n\n\n", $bystack->{$cs}->{total}, $allocs);
  }
}
