#!/bin/bash
# perl.sh <emulator> <name>, inside the Debian container: times two Perl
# benchmarks and `perl -c` of GNU parallel, and checks their output.
set -u
E=$1; N=$2; shift 2
cat > /tmp/hash.pl <<\PL
my %h; $h{$_} = $_ * 2 for 1..150000; my $s = 0; $s += $h{$_} for 1..150000; print "$s\n";
PL
cat > /tmp/mix.pl <<\PL
my @w; for my $i (1..40000) { push @w, join("-", "w$i", $i % 7, sprintf("%05d", $i)); }
my $n = 0; for (@w) { $n++ if /-3-0*(\d+)$/ && $1 % 2 }
my @s = sort { $a cmp $b } @w; sub f { my ($x) = @_; return $x < 2 ? $x : f($x-1) + f($x-2) } print "$n $s[0] ", f(20), "\n";
PL
for b in hash mix c; do
  if [ $b = c ]; then a=(-c /usr/bin/parallel); else a=(/tmp/$b.pl); fi
  want=$(/usr/bin/perl "${a[@]}" 2>&1)
  s=$(date +%s.%N)
  got=$("$E" "$@" --mount /:/ /usr/bin/perl "${a[@]}" 2>&1)
  e=$(date +%s.%N)
  [ "$got" = "$want" ] || echo "DIFFERENT perl-$b $N: $got (native $want)"
  echo "time perl-$b $N $(awk "BEGIN{print $e - $s}")"
done
