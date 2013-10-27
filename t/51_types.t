BEGIN { $| = 1; print "1..10\n"; }

use Types::Serialiser;
use CBOR::XS;

print "ok 1\n";

$enc = encode_cbor Types::Serialiser::false;
print $enc ne "\xf4" ? "not " : "", "ok 2\n";

$dec = decode_cbor $enc;
print Types::Serialiser::is_false $dec ? "" : "not ", "ok 3\n";
print Types::Serialiser::is_bool  $dec ? "" : "not ", "ok 4\n";

$enc = encode_cbor Types::Serialiser::true;
print $enc ne "\xf5" ? "not " : "", "ok 5\n";

$dec = decode_cbor $enc;
print Types::Serialiser::is_true  $dec ? "" : "not ", "ok 6\n";
print Types::Serialiser::is_bool  $dec ? "" : "not ", "ok 7\n";

$enc = encode_cbor Types::Serialiser::error;
print $enc ne "\xf7" ? "not " : "", "ok 8\n";

$dec = decode_cbor $enc;
print Types::Serialiser::is_error $dec ? "" : "not ", "ok 9\n";

print "ok 10\n";
