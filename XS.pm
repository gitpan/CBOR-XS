=head1 NAME

CBOR::XS - Concise Binary Object Representation (CBOR, RFC7049)

=encoding utf-8

=head1 SYNOPSIS

 use CBOR::XS;

 $binary_cbor_data = encode_cbor $perl_value;
 $perl_value       = decode_cbor $binary_cbor_data;

 # OO-interface

 $coder = CBOR::XS->new;
 $binary_cbor_data = $coder->encode ($perl_value);
 $perl_value       = $coder->decode ($binary_cbor_data);

 # prefix decoding

 my $many_cbor_strings = ...;
 while (length $many_cbor_strings) {
    my ($data, $length) = $cbor->decode_prefix ($many_cbor_strings);
    # data was decoded
    substr $many_cbor_strings, 0, $length, ""; # remove decoded cbor string
 }

=head1 DESCRIPTION

WARNING! This module is very new, and not very well tested (that's up to
you to do). Furthermore, details of the implementation might change freely
before version 1.0. And lastly, the object serialisation protocol depends
on a pending IANA assignment, and until that assignment is official, this
implementation is not interoperable with other implementations (even
future versions of this module) until the assignment is done.

You are still invited to try out CBOR, and this module.

This module converts Perl data structures to the Concise Binary Object
Representation (CBOR) and vice versa. CBOR is a fast binary serialisation
format that aims to use a superset of the JSON data model, i.e. when you
can represent something in JSON, you should be able to represent it in
CBOR.

In short, CBOR is a faster and very compact binary alternative to JSON,
with the added ability of supporting serialisation of Perl objects. (JSON
often compresses better than CBOR though, so if you plan to compress the
data later you might want to compare both formats first).

To give you a general idea about speed, with texts in the megabyte range,
C<CBOR::XS> usually encodes roughly twice as fast as L<Storable> or
L<JSON::XS> and decodes about 15%-30% faster than those. The shorter the
data, the worse L<Storable> performs in comparison.

As for compactness, C<CBOR::XS> encoded data structures are usually about
20% smaller than the same data encoded as (compact) JSON or L<Storable>.

The primary goal of this module is to be I<correct> and the secondary goal
is to be I<fast>. To reach the latter goal it was written in C.

See MAPPING, below, on how CBOR::XS maps perl values to CBOR values and
vice versa.

=cut

package CBOR::XS;

use common::sense;

our $VERSION = 0.08;
our @ISA = qw(Exporter);

our @EXPORT = qw(encode_cbor decode_cbor);

use Exporter;
use XSLoader;

use Types::Serialiser;

our $MAGIC = "\xd9\xd9\xf7";

=head1 FUNCTIONAL INTERFACE

The following convenience methods are provided by this module. They are
exported by default:

=over 4

=item $cbor_data = encode_cbor $perl_scalar

Converts the given Perl data structure to CBOR representation. Croaks on
error.

=item $perl_scalar = decode_cbor $cbor_data

The opposite of C<encode_cbor>: expects a valid CBOR string to parse,
returning the resulting perl scalar. Croaks on error.

=back


=head1 OBJECT-ORIENTED INTERFACE

The object oriented interface lets you configure your own encoding or
decoding style, within the limits of supported formats.

=over 4

=item $cbor = new CBOR::XS

Creates a new CBOR::XS object that can be used to de/encode CBOR
strings. All boolean flags described below are by default I<disabled>.

The mutators for flags all return the CBOR object again and thus calls can
be chained:

#TODO
   my $cbor = CBOR::XS->new->encode ({a => [1,2]});

=item $cbor = $cbor->max_depth ([$maximum_nesting_depth])

=item $max_depth = $cbor->get_max_depth

Sets the maximum nesting level (default C<512>) accepted while encoding
or decoding. If a higher nesting level is detected in CBOR data or a Perl
data structure, then the encoder and decoder will stop and croak at that
point.

Nesting level is defined by number of hash- or arrayrefs that the encoder
needs to traverse to reach a given point or the number of C<{> or C<[>
characters without their matching closing parenthesis crossed to reach a
given character in a string.

Setting the maximum depth to one disallows any nesting, so that ensures
that the object is only a single hash/object or array.

If no argument is given, the highest possible setting will be used, which
is rarely useful.

Note that nesting is implemented by recursion in C. The default value has
been chosen to be as large as typical operating systems allow without
crashing.

See SECURITY CONSIDERATIONS, below, for more info on why this is useful.

=item $cbor = $cbor->max_size ([$maximum_string_size])

=item $max_size = $cbor->get_max_size

Set the maximum length a CBOR string may have (in bytes) where decoding
is being attempted. The default is C<0>, meaning no limit. When C<decode>
is called on a string that is longer then this many bytes, it will not
attempt to decode the string but throw an exception. This setting has no
effect on C<encode> (yet).

If no argument is given, the limit check will be deactivated (same as when
C<0> is specified).

See SECURITY CONSIDERATIONS, below, for more info on why this is useful.

=item $cbor_data = $cbor->encode ($perl_scalar)

Converts the given Perl data structure (a scalar value) to its CBOR
representation.

=item $perl_scalar = $cbor->decode ($cbor_data)

The opposite of C<encode>: expects CBOR data and tries to parse it,
returning the resulting simple scalar or reference. Croaks on error.

=item ($perl_scalar, $octets) = $cbor->decode_prefix ($cbor_data)

This works like the C<decode> method, but instead of raising an exception
when there is trailing garbage after the CBOR string, it will silently
stop parsing there and return the number of characters consumed so far.

This is useful if your CBOR texts are not delimited by an outer protocol
and you need to know where the first CBOR string ends amd the next one
starts.

   CBOR::XS->new->decode_prefix ("......")
   => ("...", 3)

=back


=head1 MAPPING

This section describes how CBOR::XS maps Perl values to CBOR values and
vice versa. These mappings are designed to "do the right thing" in most
circumstances automatically, preserving round-tripping characteristics
(what you put in comes out as something equivalent).

For the more enlightened: note that in the following descriptions,
lowercase I<perl> refers to the Perl interpreter, while uppercase I<Perl>
refers to the abstract Perl language itself.


=head2 CBOR -> PERL

=over 4

=item integers

CBOR integers become (numeric) perl scalars. On perls without 64 bit
support, 64 bit integers will be truncated or otherwise corrupted.

=item byte strings

Byte strings will become octet strings in Perl (the byte values 0..255
will simply become characters of the same value in Perl).

=item UTF-8 strings

UTF-8 strings in CBOR will be decoded, i.e. the UTF-8 octets will be
decoded into proper Unicode code points. At the moment, the validity of
the UTF-8 octets will not be validated - corrupt input will result in
corrupted Perl strings.

=item arrays, maps

CBOR arrays and CBOR maps will be converted into references to a Perl
array or hash, respectively. The keys of the map will be stringified
during this process.

=item null

CBOR null becomes C<undef> in Perl.

=item true, false, undefined

These CBOR values become C<Types:Serialiser::true>,
C<Types:Serialiser::false> and C<Types::Serialiser::error>,
respectively. They are overloaded to act almost exactly like the numbers
C<1> and C<0> (for true and false) or to throw an exception on access (for
error). See the L<Types::Serialiser> manpage for details.

=item CBOR tag 256 (perl object)

The tag value C<256> (TODO: pending iana registration) will be used
to deserialise a Perl object serialised with C<FREEZE>. See L<OBJECT
SERIALISATION>, below, for details.

=item CBOR tag 55799 (magic header)

The tag 55799 is ignored (this tag implements the magic header).

=item other CBOR tags

Tagged items consists of a numeric tag and another CBOR value. Tags not
handled internally are currently converted into a L<CBOR::XS::Tagged>
object, which is simply a blessed array reference consisting of the
numeric tag value followed by the (decoded) CBOR value.

In the future, support for user-supplied conversions might get added.

=item anything else

Anything else (e.g. unsupported simple values) will raise a decoding
error.

=back


=head2 PERL -> CBOR

The mapping from Perl to CBOR is slightly more difficult, as Perl is a
truly typeless language, so we can only guess which CBOR type is meant by
a Perl value.

=over 4

=item hash references

Perl hash references become CBOR maps. As there is no inherent ordering in
hash keys (or CBOR maps), they will usually be encoded in a pseudo-random
order.

Currently, tied hashes will use the indefinite-length format, while normal
hashes will use the fixed-length format.

=item array references

Perl array references become fixed-length CBOR arrays.

=item other references

Other unblessed references are generally not allowed and will cause an
exception to be thrown, except for references to the integers C<0> and
C<1>, which get turned into false and true in CBOR.

=item CBOR::XS::Tagged objects

Objects of this type must be arrays consisting of a single C<[tag, value]>
pair. The (numerical) tag will be encoded as a CBOR tag, the value will
be encoded as appropriate for the value. You cna use C<CBOR::XS::tag> to
create such objects.

=item Types::Serialiser::true, Types::Serialiser::false, Types::Serialiser::error

These special values become CBOR true, CBOR false and CBOR undefined
values, respectively. You can also use C<\1>, C<\0> and C<\undef> directly
if you want.

=item other blessed objects

Other blessed objects are serialised via C<TO_CBOR> or C<FREEZE>. See
L<OBJECT SERIALISATION>, below, for details.

=item simple scalars

TODO
Simple Perl scalars (any scalar that is not a reference) are the most
difficult objects to encode: CBOR::XS will encode undefined scalars as
CBOR null values, scalars that have last been used in a string context
before encoding as CBOR strings, and anything else as number value:

   # dump as number
   encode_cbor [2]                      # yields [2]
   encode_cbor [-3.0e17]                # yields [-3e+17]
   my $value = 5; encode_cbor [$value]  # yields [5]

   # used as string, so dump as string
   print $value;
   encode_cbor [$value]                 # yields ["5"]

   # undef becomes null
   encode_cbor [undef]                  # yields [null]

You can force the type to be a CBOR string by stringifying it:

   my $x = 3.1; # some variable containing a number
   "$x";        # stringified
   $x .= "";    # another, more awkward way to stringify
   print $x;    # perl does it for you, too, quite often

You can force the type to be a CBOR number by numifying it:

   my $x = "3"; # some variable containing a string
   $x += 0;     # numify it, ensuring it will be dumped as a number
   $x *= 1;     # same thing, the choice is yours.

You can not currently force the type in other, less obscure, ways. Tell me
if you need this capability (but don't forget to explain why it's needed
:).

Perl values that seem to be integers generally use the shortest possible
representation. Floating-point values will use either the IEEE single
format if possible without loss of precision, otherwise the IEEE double
format will be used. Perls that use formats other than IEEE double to
represent numerical values are supported, but might suffer loss of
precision.

=back

=head2 OBJECT SERIALISATION

This module knows two way to serialise a Perl object: The CBOR-specific
way, and the generic way.

Whenever the encoder encounters a Perl object that it cnanot serialise
directly (most of them), it will first look up the C<TO_CBOR> method on
it.

If it has a C<TO_CBOR> method, it will call it with the object as only
argument, and expects exactly one return value, which it will then
substitute and encode it in the place of the object.

Otherwise, it will look up the C<FREEZE> method. If it exists, it will
call it with the object as first argument, and the constant string C<CBOR>
as the second argument, to distinguish it from other serialisers.

The C<FREEZE> method can return any number of values (i.e. zero or
more). These will be encoded as CBOR perl object, together with the
classname.

If an object supports neither C<TO_CBOR> nor C<FREEZE>, encoding will fail
with an error.

Objects encoded via C<TO_CBOR> cannot be automatically decoded, but
objects encoded via C<FREEZE> can be decoded using the following protocol:

When an encoded CBOR perl object is encountered by the decoder, it will
look up the C<THAW> method, by using the stored classname, and will fail
if the method cannot be found.

After the lookup it will call the C<THAW> method with the stored classname
as first argument, the constant string C<CBOR> as second argument, and all
values returned by C<FREEZE> as remaining arguments.

=head4 EXAMPLES

Here is an example C<TO_CBOR> method:

   sub My::Object::TO_CBOR {
      my ($obj) = @_;

      ["this is a serialised My::Object object", $obj->{id}]
   }

When a C<My::Object> is encoded to CBOR, it will instead encode a simple
array with two members: a string, and the "object id". Decoding this CBOR
string will yield a normal perl array reference in place of the object.

A more useful and practical example would be a serialisation method for
the URI module. CBOR has a custom tag value for URIs, namely 32:

  sub URI::TO_CBOR {
     my ($self) = @_;
     my $uri = "$self"; # stringify uri
     utf8::upgrade $uri; # make sure it will be encoded as UTF-8 string
     CBOR::XS::tagged 32, "$_[0]"
  }

This will encode URIs as a UTF-8 string with tag 32, which indicates an
URI.

Decoding such an URI will not (currently) give you an URI object, but
instead a CBOR::XS::Tagged object with tag number 32 and the string -
exactly what was returned by C<TO_CBOR>.

To serialise an object so it can automatically be deserialised, you need
to use C<FREEZE> and C<THAW>. To take the URI module as example, this
would be a possible implementation:

   sub URI::FREEZE {
      my ($self, $serialiser) = @_;
      "$self" # encode url string
   }

   sub URI::THAW {
      my ($class, $serialiser, $uri) = @_;

      $class->new ($uri)
   }

Unlike C<TO_CBOR>, multiple values can be returned by C<FREEZE>. For
example, a C<FREEZE> method that returns "type", "id" and "variant" values
would cause an invocation of C<THAW> with 5 arguments:

   sub My::Object::FREEZE {
      my ($self, $serialiser) = @_;

      ($self->{type}, $self->{id}, $self->{variant})
   }

   sub My::Object::THAW {
      my ($class, $serialiser, $type, $id, $variant) = @_;

      $class-<new (type => $type, id => $id, variant => $variant)
   }


=head1 MAGIC HEADER

There is no way to distinguish CBOR from other formats
programmatically. To make it easier to distinguish CBOR from other
formats, the CBOR specification has a special "magic string" that can be
prepended to any CBOR string without changing it's meaning.

This string is available as C<$CBOR::XS::MAGIC>. This module does not
prepend this string tot he CBOR data it generates, but it will ignroe it
if present, so users can prepend this string as a "file type" indicator as
required.


=head1 THE CBOR::XS::Tagged CLASS

CBOR has the concept of tagged values - any CBOR value can be tagged with
a numeric 64 bit number, which are centrally administered.

C<CBOR::XS> handles a few tags internally when en- or decoding. You can
also create tags yourself by encoding C<CBOR::XS::Tagged> objects, and the
decoder will create C<CBOR::XS::Tagged> objects itself when it hits an
unknown tag.

These objects are simply blessed array references - the first member of
the array being the numerical tag, the second being the value.

You can interact with C<CBOR::XS::Tagged> objects in the following ways:

=over 4

=item $tagged = CBOR::XS::tag $tag, $value

This function(!) creates a new C<CBOR::XS::Tagged> object using the given
C<$tag> (0..2**64-1) to tag the given C<$value> (which can be any Perl
value that can be encoded in CBOR, including serialisable Perl objects and
C<CBOR::XS::Tagged> objects).

=item $tagged->[0]

=item $tagged->[0] = $new_tag

=item $tag = $tagged->tag

=item $new_tag = $tagged->tag ($new_tag)

Access/mutate the tag.

=item $tagged->[1]

=item $tagged->[1] = $new_value

=item $value = $tagged->value

=item $new_value = $tagged->value ($new_value)

Access/mutate the tagged value.

=back

=cut

sub tag($$) {
   bless [@_], CBOR::XS::Tagged::;
}

sub CBOR::XS::Tagged::tag {
   $_[0][0] = $_[1] if $#_;
   $_[0][0]
}

sub CBOR::XS::Tagged::value {
   $_[0][1] = $_[1] if $#_;
   $_[0][1]
}

=head2 EXAMPLES

Here are some examples of C<CBOR::XS::Tagged> uses to tag objects.

You can look up CBOR tag value and emanings in the IANA registry at
L<http://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>.

Prepend a magic header (C<$CBOR::XS::MAGIC>):

   my $cbor = encode_cbor CBOR::XS::tag 55799, $value;
   # same as:
   my $cbor = $CBOR::XS::MAGIC . encode_cbor $value;

Serialise some URIs and a regex in an array:

   my $cbor = encode_cbor [
      (CBOR::XS::tag 32, "http://www.nethype.de/"),
      (CBOR::XS::tag 32, "http://software.schmorp.de/"),
      (CBOR::XS::tag 35, "^[Pp][Ee][Rr][lL]\$"),
   ];

Wrap CBOR data in CBOR:

   my $cbor_cbor = encode_cbor
      CBOR::XS::tag 24,
         encode_cbor [1, 2, 3];

=head1 CBOR and JSON

CBOR is supposed to implement a superset of the JSON data model, and is,
with some coercion, able to represent all JSON texts (something that other
"binary JSON" formats such as BSON generally do not support).

CBOR implements some extra hints and support for JSON interoperability,
and the spec offers further guidance for conversion between CBOR and
JSON. None of this is currently implemented in CBOR, and the guidelines
in the spec do not result in correct round-tripping of data. If JSON
interoperability is improved in the future, then the goal will be to
ensure that decoded JSON data will round-trip encoding and decoding to
CBOR intact.


=head1 SECURITY CONSIDERATIONS

When you are using CBOR in a protocol, talking to untrusted potentially
hostile creatures requires relatively few measures.

First of all, your CBOR decoder should be secure, that is, should not have
any buffer overflows. Obviously, this module should ensure that and I am
trying hard on making that true, but you never know.

Second, you need to avoid resource-starving attacks. That means you should
limit the size of CBOR data you accept, or make sure then when your
resources run out, that's just fine (e.g. by using a separate process that
can crash safely). The size of a CBOR string in octets is usually a good
indication of the size of the resources required to decode it into a Perl
structure. While CBOR::XS can check the size of the CBOR text, it might be
too late when you already have it in memory, so you might want to check
the size before you accept the string.

Third, CBOR::XS recurses using the C stack when decoding objects and
arrays. The C stack is a limited resource: for instance, on my amd64
machine with 8MB of stack size I can decode around 180k nested arrays but
only 14k nested CBOR objects (due to perl itself recursing deeply on croak
to free the temporary). If that is exceeded, the program crashes. To be
conservative, the default nesting limit is set to 512. If your process
has a smaller stack, you should adjust this setting accordingly with the
C<max_depth> method.

Something else could bomb you, too, that I forgot to think of. In that
case, you get to keep the pieces. I am always open for hints, though...

Also keep in mind that CBOR::XS might leak contents of your Perl data
structures in its error messages, so when you serialise sensitive
information you might want to make sure that exceptions thrown by CBOR::XS
will not end up in front of untrusted eyes.

=head1 CBOR IMPLEMENTATION NOTES

This section contains some random implementation notes. They do not
describe guaranteed behaviour, but merely behaviour as-is implemented
right now.

64 bit integers are only properly decoded when Perl was built with 64 bit
support.

Strings and arrays are encoded with a definite length. Hashes as well,
unless they are tied (or otherwise magical).

Only the double data type is supported for NV data types - when Perl uses
long double to represent floating point values, they might not be encoded
properly. Half precision types are accepted, but not encoded.

Strict mode and canonical mode are not implemented.


=head1 THREADS

This module is I<not> guaranteed to be thread safe and there are no
plans to change this until Perl gets thread support (as opposed to the
horribly slow so-called "threads" which are simply slow and bloated
process simulations - use fork, it's I<much> faster, cheaper, better).

(It might actually work, but you have been warned).


=head1 BUGS

While the goal of this module is to be correct, that unfortunately does
not mean it's bug-free, only that I think its design is bug-free. If you
keep reporting bugs they will be fixed swiftly, though.

Please refrain from using rt.cpan.org or any other bug reporting
service. I put the contact address into my modules for a reason.

=cut

XSLoader::load "CBOR::XS", $VERSION;

=head1 SEE ALSO

The L<JSON> and L<JSON::XS> modules that do similar, but human-readable,
serialisation.

The L<Types::Serialiser> module provides the data model for true, false
and error values.

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

1

