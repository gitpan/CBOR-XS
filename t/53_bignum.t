BEGIN { $| = 1; print "1..100\n"; }
BEGIN { $^W = 0 } # hate

use CBOR::XS;

print "ok 1\n";

my $t = decode_cbor pack "H*", "82c48221196ab3c5822003";

print $t->[0] eq "273.15" ? "" : "not ", "ok 2 # $t->[0]\n";
print $t->[1] eq    "1.5" ? "" : "not ", "ok 3 # $t->[1]\n";

$t = encode_cbor $t;

print $t eq (pack "H*", "82c48221196ab3c482200f") ? "" : "not ", "ok 4 # ", (unpack "H*", $t), "\n";

# Math::BigFloat is loaded by now...

for (5..99) {
   my $n = Math::BigFloat->new ((int rand 1e9) . "." . (int rand 1e9) . "e" . ((int rand 1e8) - 0.5e8));
   my $m = decode_cbor encode_cbor $n;

   $n = $n->bsstr;
   $m = $m->bsstr;

   print $n != $m ? "not " : "ok $_ # $n eq $m\n";
}

print "ok 100\n";

