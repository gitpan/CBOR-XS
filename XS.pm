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

This module converts Perl data structures to the Concise Binary Object
Representation (CBOR) and vice versa. CBOR is a fast binary serialisation
format that aims to use an (almost) superset of the JSON data model, i.e.
when you can represent something useful in JSON, you should be able to
represent it in CBOR.

In short, CBOR is a faster and quite compact binary alternative to JSON,
with the added ability of supporting serialisation of Perl objects. (JSON
often compresses better than CBOR though, so if you plan to compress the
data later and speed is less important you might want to compare both
formats first).

To give you a general idea about speed, with texts in the megabyte range,
C<CBOR::XS> usually encodes roughly twice as fast as L<Storable> or
L<JSON::XS> and decodes about 15%-30% faster than those. The shorter the
data, the worse L<Storable> performs in comparison.

Regarding compactness, C<CBOR::XS>-encoded data structures are usually
about 20% smaller than the same data encoded as (compact) JSON or
L<Storable>.

In addition to the core CBOR data format, this module implements a
number of extensions, to support cyclic and shared data structures
(see C<allow_sharing> and C<allow_cycles>), string deduplication (see
C<pack_strings>) and scalar references (always enabled).

The primary goal of this module is to be I<correct> and the secondary goal
is to be I<fast>. To reach the latter goal it was written in C.

See MAPPING, below, on how CBOR::XS maps perl values to CBOR values and
vice versa.

=cut

package CBOR::XS;

use common::sense;

our $VERSION = 1.26;
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

=item $cbor = $cbor->allow_unknown ([$enable])

=item $enabled = $cbor->get_allow_unknown

If C<$enable> is true (or missing), then C<encode> will I<not> throw an
exception when it encounters values it cannot represent in CBOR (for
example, filehandles) but instead will encode a CBOR C<error> value.

If C<$enable> is false (the default), then C<encode> will throw an
exception when it encounters anything it cannot encode as CBOR.

This option does not affect C<decode> in any way, and it is recommended to
leave it off unless you know your communications partner.

=item $cbor = $cbor->allow_sharing ([$enable])

=item $enabled = $cbor->get_allow_sharing

If C<$enable> is true (or missing), then C<encode> will not double-encode
values that have been referenced before (e.g. when the same object, such
as an array, is referenced multiple times), but instead will emit a
reference to the earlier value.

This means that such values will only be encoded once, and will not result
in a deep cloning of the value on decode, in decoders supporting the value
sharing extension. This also makes it possible to encode cyclic data
structures (which need C<allow_cycles> to ne enabled to be decoded by this
module).

It is recommended to leave it off unless you know your
communication partner supports the value sharing extensions to CBOR
(L<http://cbor.schmorp.de/value-sharing>), as without decoder support, the
resulting data structure might be unusable.

Detecting shared values incurs a runtime overhead when values are encoded
that have a reference counter large than one, and might unnecessarily
increase the encoded size, as potentially shared values are encode as
shareable whether or not they are actually shared.

At the moment, only targets of references can be shared (e.g. scalars,
arrays or hashes pointed to by a reference). Weirder constructs, such as
an array with multiple "copies" of the I<same> string, which are hard but
not impossible to create in Perl, are not supported (this is the same as
with L<Storable>).

If C<$enable> is false (the default), then C<encode> will encode shared
data structures repeatedly, unsharing them in the process. Cyclic data
structures cannot be encoded in this mode.

This option does not affect C<decode> in any way - shared values and
references will always be decoded properly if present.

=item $cbor = $cbor->allow_cycles ([$enable])

=item $enabled = $cbor->get_allow_cycles

If C<$enable> is true (or missing), then C<decode> will happily decode
self-referential (cyclic) data structures. By default these will not be
decoded, as they need manual cleanup to avoid memory leaks, so code that
isn't prepared for this will not leak memory.

If C<$enable> is false (the default), then C<decode> will throw an error
when it encounters a self-referential/cyclic data structure.

FUTURE DIRECTION: the motivation behind this option is to avoid I<real>
cycles - future versions of this module might chose to decode cyclic data
structures using weak references when this option is off, instead of
throwing an error.

This option does not affect C<encode> in any way - shared values and
references will always be encoded properly if present.

=item $cbor = $cbor->pack_strings ([$enable])

=item $enabled = $cbor->get_pack_strings

If C<$enable> is true (or missing), then C<encode> will try not to encode
the same string twice, but will instead encode a reference to the string
instead. Depending on your data format, this can save a lot of space, but
also results in a very large runtime overhead (expect encoding times to be
2-4 times as high as without).

It is recommended to leave it off unless you know your
communications partner supports the stringref extension to CBOR
(L<http://cbor.schmorp.de/stringref>), as without decoder support, the
resulting data structure might not be usable.

If C<$enable> is false (the default), then C<encode> will encode strings
the standard CBOR way.

This option does not affect C<decode> in any way - string references will
always be decoded properly if present.

=item $cbor = $cbor->validate_utf8 ([$enable])

=item $enabled = $cbor->get_validate_utf8

If C<$enable> is true (or missing), then C<decode> will validate that
elements (text strings) containing UTF-8 data in fact contain valid UTF-8
data (instead of blindly accepting it). This validation obviously takes
extra time during decoding.

The concept of "valid UTF-8" used is perl's concept, which is a superset
of the official UTF-8.

If C<$enable> is false (the default), then C<decode> will blindly accept
UTF-8 data, marking them as valid UTF-8 in the resulting data structure
regardless of whether thats true or not.

Perl isn't too happy about corrupted UTF-8 in strings, but should
generally not crash or do similarly evil things. Extensions might be not
so forgiving, so it's recommended to turn on this setting if you receive
untrusted CBOR.

This option does not affect C<encode> in any way - strings that are
supposedly valid UTF-8 will simply be dumped into the resulting CBOR
string without checking whether that is, in fact, true or not.

=item $cbor = $cbor->filter ([$cb->($tag, $value)])

=item $cb_or_undef = $cbor->get_filter

Sets or replaces the tagged value decoding filter (when C<$cb> is
specified) or clears the filter (if no argument or C<undef> is provided).

The filter callback is called only during decoding, when a non-enforced
tagged value has been decoded (see L<TAG HANDLING AND EXTENSIONS> for a
list of enforced tags). For specific tags, it's often better to provide a
default converter using the C<%CBOR::XS::FILTER> hash (see below).

The first argument is the numerical tag, the second is the (decoded) value
that has been tagged.

The filter function should return either exactly one value, which will
replace the tagged value in the decoded data structure, or no values,
which will result in default handling, which currently means the decoder
creates a C<CBOR::XS::Tagged> object to hold the tag and the value.

When the filter is cleared (the default state), the default filter
function, C<CBOR::XS::default_filter>, is used. This function simply looks
up the tag in the C<%CBOR::XS::FILTER> hash. If an entry exists it must be
a code reference that is called with tag and value, and is responsible for
decoding the value. If no entry exists, it returns no values.

Example: decode all tags not handled internally into C<CBOR::XS::Tagged>
objects, with no other special handling (useful when working with
potentially "unsafe" CBOR data).

   CBOR::XS->new->filter (sub { })->decode ($cbor_data);

Example: provide a global filter for tag 1347375694, converting the value
into some string form.

   $CBOR::XS::FILTER{1347375694} = sub {
      my ($tag, $value);

      "tag 1347375694 value $value"
   };

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

=head2 INCREMENTAL PARSING

In some cases, there is the need for incremental parsing of JSON
texts. While this module always has to keep both CBOR text and resulting
Perl data structure in memory at one time, it does allow you to parse a
CBOR stream incrementally, using a similar to using "decode_prefix" to see
if a full CBOR object is available, but is much more efficient.

It basically works by parsing as much of a CBOR string as possible - if
the CBOR data is not complete yet, the pasrer will remember where it was,
to be able to restart when more data has been accumulated. Once enough
data is available to either decode a complete CBOR value or raise an
error, a real decode will be attempted.

A typical use case would be a network protocol that consists of sending
and receiving CBOR-encoded messages. The solution that works with CBOR and
about anything else is by prepending a length to every CBOR value, so the
receiver knows how many octets to read. More compact (and slightly slower)
would be to just send CBOR values back-to-back, as C<CBOR::XS> knows where
a CBOR value ends, and doesn't need an explicit length.

The following methods help with this:

=over 4

=item @decoded = $cbor->incr_parse ($buffer)

This method attempts to decode exactly one CBOR value from the beginning
of the given C<$buffer>. The value is removed from the C<$buffer> on
success. When C<$buffer> doesn't contain a complete value yet, it returns
nothing. Finally, when the C<$buffer> doesn't start with something
that could ever be a valid CBOR value, it raises an exception, just as
C<decode> would. In the latter case the decoder state is undefined and
must be reset before being able to parse further.

This method modifies the C<$buffer> in place. When no CBOR value can be
decoded, the decoder stores the current string offset. On the next call,
continues decoding at the place where it stopped before. For this to make
sense, the C<$buffer> must begin with the same octets as on previous
unsuccessful calls.

You can call this method in scalar context, in which case it either
returns a decoded value or C<undef>. This makes it impossible to
distinguish between CBOR null values (which decode to C<undef>) and an
unsuccessful decode, which is often acceptable.

=item @decoded = $cbor->incr_parse_multiple ($buffer)

Same as C<incr_parse>, but attempts to decode as many CBOR values as
possible in one go, instead of at most one. Calls to C<incr_parse> and
C<incr_parse_multiple> can be interleaved.

=item $cbor->incr_reset

Resets the incremental decoder. This throws away any saved state, so that
subsequent calls to C<incr_parse> or C<incr_parse_multiple> start to parse
a new CBOR value from the beginning of the C<$buffer> again.

This method can be caled at any time, but it I<must> be called if you want
to change your C<$buffer> or there was a decoding error and you want to
reuse the C<$cbor> object for future incremental parsings.

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

Byte strings will become octet strings in Perl (the Byte values 0..255
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

=item tagged values

Tagged items consists of a numeric tag and another CBOR value.

See L<TAG HANDLING AND EXTENSIONS> and the description of C<< ->filter >>
for details on which tags are handled how.

=item anything else

Anything else (e.g. unsupported simple values) will raise a decoding
error.

=back


=head2 PERL -> CBOR

The mapping from Perl to CBOR is slightly more difficult, as Perl is a
typeless language. That means this module can only guess which CBOR type
is meant by a perl value.

=over 4

=item hash references

Perl hash references become CBOR maps. As there is no inherent ordering in
hash keys (or CBOR maps), they will usually be encoded in a pseudo-random
order. This order can be different each time a hahs is encoded.

Currently, tied hashes will use the indefinite-length format, while normal
hashes will use the fixed-length format.

=item array references

Perl array references become fixed-length CBOR arrays.

=item other references

Other unblessed references will be represented using
the indirection tag extension (tag value C<22098>,
L<http://cbor.schmorp.de/indirection>). CBOR decoders are guaranteed
to be able to decode these values somehow, by either "doing the right
thing", decoding into a generic tagged object, simply ignoring the tag, or
something else.

=item CBOR::XS::Tagged objects

Objects of this type must be arrays consisting of a single C<[tag, value]>
pair. The (numerical) tag will be encoded as a CBOR tag, the value will
be encoded as appropriate for the value. You must use C<CBOR::XS::tag> to
create such objects.

=item Types::Serialiser::true, Types::Serialiser::false, Types::Serialiser::error

These special values become CBOR true, CBOR false and CBOR undefined
values, respectively. You can also use C<\1>, C<\0> and C<\undef> directly
if you want.

=item other blessed objects

Other blessed objects are serialised via C<TO_CBOR> or C<FREEZE>. See
L<TAG HANDLING AND EXTENSIONS> for specific classes handled by this
module, and L<OBJECT SERIALISATION> for generic object serialisation.

=item simple scalars

Simple Perl scalars (any scalar that is not a reference) are the most
difficult objects to encode: CBOR::XS will encode undefined scalars as
CBOR null values, scalars that have last been used in a string context
before encoding as CBOR strings, and anything else as number value:

   # dump as number
   encode_cbor [2]                      # yields [2]
   encode_cbor [-3.0e17]                # yields [-3e+17]
   my $value = 5; encode_cbor [$value]  # yields [5]

   # used as string, so dump as string (either byte or text)
   print $value;
   encode_cbor [$value]                 # yields ["5"]

   # undef becomes null
   encode_cbor [undef]                  # yields [null]

You can force the type to be a CBOR string by stringifying it:

   my $x = 3.1; # some variable containing a number
   "$x";        # stringified
   $x .= "";    # another, more awkward way to stringify
   print $x;    # perl does it for you, too, quite often

You can force whether a string ie encoded as byte or text string by using
C<utf8::upgrade> and C<utf8::downgrade>):

  utf8::upgrade $x;   # encode $x as text string
  utf8::downgrade $x; # encode $x as byte string

Perl doesn't define what operations up- and downgrade strings, so if the
difference between byte and text is important, you should up- or downgrade
your string as late as possible before encoding.

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

This module implements both a CBOR-specific and the generic
L<Types::Serialier> object serialisation protocol. The following
subsections explain both methods.

=head3 ENCODING

This module knows two way to serialise a Perl object: The CBOR-specific
way, and the generic way.

Whenever the encoder encounters a Perl object that it cannot serialise
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

These methods I<MUST NOT> change the data structure that is being
serialised. Failure to comply to this can result in memory corruption -
and worse.

If an object supports neither C<TO_CBOR> nor C<FREEZE>, encoding will fail
with an error.

=head3 DECODING

Objects encoded via C<TO_CBOR> cannot (normally) be automatically decoded,
but objects encoded via C<FREEZE> can be decoded using the following
protocol:

When an encoded CBOR perl object is encountered by the decoder, it will
look up the C<THAW> method, by using the stored classname, and will fail
if the method cannot be found.

After the lookup it will call the C<THAW> method with the stored classname
as first argument, the constant string C<CBOR> as second argument, and all
values returned by C<FREEZE> as remaining arguments.

=head3 EXAMPLES

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
     CBOR::XS::tag 32, "$_[0]"
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
prepended to any CBOR string without changing its meaning.

This string is available as C<$CBOR::XS::MAGIC>. This module does not
prepend this string to the CBOR data it generates, but it will ignore it
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

=head1 TAG HANDLING AND EXTENSIONS

This section describes how this module handles specific tagged values
and extensions. If a tag is not mentioned here and no additional filters
are provided for it, then the default handling applies (creating a
CBOR::XS::Tagged object on decoding, and only encoding the tag when
explicitly requested).

Tags not handled specifically are currently converted into a
L<CBOR::XS::Tagged> object, which is simply a blessed array reference
consisting of the numeric tag value followed by the (decoded) CBOR value.

Future versions of this module reserve the right to special case
additional tags (such as base64url).

=head2 ENFORCED TAGS

These tags are always handled when decoding, and their handling cannot be
overriden by the user.

=over 4

=item 26 (perl-object, L<http://cbor.schmorp.de/perl-object>)

These tags are automatically created (and decoded) for serialisable
objects using the C<FREEZE/THAW> methods (the L<Types::Serialier> object
serialisation protocol). See L<OBJECT SERIALISATION> for details.

=item 28, 29 (shareable, sharedref, L <http://cbor.schmorp.de/value-sharing>)

These tags are automatically decoded when encountered (and they do not
result in a cyclic data structure, see C<allow_cycles>), resulting in
shared values in the decoded object. They are only encoded, however, when
C<allow_sharing> is enabled.

Not all shared values can be successfully decoded: values that reference
themselves will I<currently> decode as C<undef> (this is not the same
as a reference pointing to itself, which will be represented as a value
that contains an indirect reference to itself - these will be decoded
properly).

Note that considerably more shared value data structures can be decoded
than will be encoded - currently, only values pointed to by references
will be shared, others will not. While non-reference shared values can be
generated in Perl with some effort, they were considered too unimportant
to be supported in the encoder. The decoder, however, will decode these
values as shared values.

=item 256, 25 (stringref-namespace, stringref, L <http://cbor.schmorp.de/stringref>)

These tags are automatically decoded when encountered. They are only
encoded, however, when C<pack_strings> is enabled.

=item 22098 (indirection, L<http://cbor.schmorp.de/indirection>)

This tag is automatically generated when a reference are encountered (with
the exception of hash and array refernces). It is converted to a reference
when decoding.

=item 55799 (self-describe CBOR, RFC 7049)

This value is not generated on encoding (unless explicitly requested by
the user), and is simply ignored when decoding.

=back

=head2 NON-ENFORCED TAGS

These tags have default filters provided when decoding. Their handling can
be overriden by changing the C<%CBOR::XS::FILTER> entry for the tag, or by
providing a custom C<filter> callback when decoding.

When they result in decoding into a specific Perl class, the module
usually provides a corresponding C<TO_CBOR> method as well.

When any of these need to load additional modules that are not part of the
perl core distribution (e.g. L<URI>), it is (currently) up to the user to
provide these modules. The decoding usually fails with an exception if the
required module cannot be loaded.

=over 4

=item 0, 1 (date/time string, seconds since the epoch)

These tags are decoded into L<Time::Piece> objects. The corresponding
C<Time::Piece::TO_CBOR> method always encodes into tag 1 values currently.

The L<Time::Piece> API is generally surprisingly bad, and fractional
seconds are only accidentally kept intact, so watch out. On the plus side,
the module comes with perl since 5.10, which has to count for something.

=item 2, 3 (positive/negative bignum)

These tags are decoded into L<Math::BigInt> objects. The corresponding
C<Math::BigInt::TO_CBOR> method encodes "small" bigints into normal CBOR
integers, and others into positive/negative CBOR bignums.

=item 4, 5 (decimal fraction/bigfloat)

Both decimal fractions and bigfloats are decoded into L<Math::BigFloat>
objects. The corresponding C<Math::BigFloat::TO_CBOR> method I<always>
encodes into a decimal fraction.

CBOR cannot represent bigfloats with I<very> large exponents - conversion
of such big float objects is undefined.

Also, NaN and infinities are not encoded properly.

=item 21, 22, 23 (expected later JSON conversion)

CBOR::XS is not a CBOR-to-JSON converter, and will simply ignore these
tags.

=item 32 (URI)

These objects decode into L<URI> objects. The corresponding
C<URI::TO_CBOR> method again results in a CBOR URI value.

=back

=cut

our %FILTER = (
   # 0 # rfc4287 datetime, utf-8
   # 1 # unix timestamp, any

   2 => sub { # pos bigint
      require Math::BigInt;
      Math::BigInt->new ("0x" . unpack "H*", pop)
   },

   3 => sub { # neg bigint
      require Math::BigInt;
      -Math::BigInt->new ("0x" . unpack "H*", pop)
   },

   4 => sub { # decimal fraction, array
      require Math::BigFloat;
      Math::BigFloat->new ($_[1][1] . "E" . $_[1][0])
   },

   5 => sub { # bigfloat, array
      require Math::BigFloat;
      scalar Math::BigFloat->new ($_[1][1])->blsft ($_[1][0], 2)
   },

   21 => sub { pop }, # expected conversion to base64url encoding
   22 => sub { pop }, # expected conversion to base64 encoding
   23 => sub { pop }, # expected conversion to base16 encoding

   # 24 # embedded cbor, byte string

   32 => sub {
      require URI;
      URI->new (pop)
   },

   # 33 # base64url rfc4648, utf-8
   # 34 # base64 rfc46484, utf-8
   # 35 # regex pcre/ecma262, utf-8
   # 36 # mime message rfc2045, utf-8
);


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


=head1 LIMITATIONS ON PERLS WITHOUT 64-BIT INTEGER SUPPORT

On perls that were built without 64 bit integer support (these are rare
nowadays, even on 32 bit architectures), support for any kind of 64 bit
integer in CBOR is very limited - most likely, these 64 bit values will
be truncated, corrupted, or otherwise not decoded correctly. This also
includes string, array and map sizes that are stored as 64 bit integers.


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

our %FILTER = (
   0 => sub { # rfc4287 datetime, utf-8
      require Time::Piece;
      # Time::Piece::Strptime uses the "incredibly flexible date parsing routine"
      # from FreeBSD, which can't parse ISO 8601, RFC3339, RFC4287 or much of anything
      # else either. Whats incredibe over standard strptime totally escapes me.
      # doesn't do fractional times, either. sigh.
      # In fact, it's all a lie, it uses whatever strptime it wants, and of course,
      # they are all incomptible. The openbsd one simply ignores %z (but according to the
      # docs, it would be much more incredibly flexible indeed. If it worked, that is.).
      scalar eval {
         my $s = $_[1];

         $s =~ s/Z$/+00:00/;
         $s =~ s/(\.[0-9]+)?([+-][0-9][0-9]):([0-9][0-9])$//
            or die;

         my $b = $1 - ($2 * 60 + $3) * 60; # fractional part + offset. hopefully
         my $d = Time::Piece->strptime ($s, "%Y-%m-%dT%H:%M:%S");

         Time::Piece::gmtime ($d->epoch + $b)
      } || die "corrupted CBOR date/time string ($_[0])";
   },
 
   1 => sub { # seconds since the epoch, possibly fractional
      require Time::Piece;
      scalar Time::Piece::gmtime (pop)
   },

   2 => sub { # pos bigint
      require Math::BigInt;
      Math::BigInt->new ("0x" . unpack "H*", pop)
   },

   3 => sub { # neg bigint
      require Math::BigInt;
      -Math::BigInt->new ("0x" . unpack "H*", pop)
   },

   4 => sub { # decimal fraction, array
      require Math::BigFloat;
      Math::BigFloat->new ($_[1][1] . "E" . $_[1][0])
   },

   5 => sub { # bigfloat, array
      require Math::BigFloat;
      scalar Math::BigFloat->new ($_[1][1])->blsft ($_[1][0], 2)
   },

   21 => sub { pop }, # expected conversion to base64url encoding
   22 => sub { pop }, # expected conversion to base64 encoding
   23 => sub { pop }, # expected conversion to base16 encoding

   # 24 # embedded cbor, byte string

   32 => sub {
      require URI;
      URI->new (pop)
   },

   # 33 # base64url rfc4648, utf-8
   # 34 # base64 rfc46484, utf-8
   # 35 # regex pcre/ecma262, utf-8
   # 36 # mime message rfc2045, utf-8
);

sub CBOR::XS::default_filter {
   &{ $FILTER{$_[0]} or return }
}

sub URI::TO_CBOR {
   my $uri = $_[0]->as_string;
   utf8::upgrade $uri;
   tag 32, $uri
}

sub Math::BigInt::TO_CBOR {
   if ($_[0] >= -2147483648 && $_[0] <= 2147483647) {
      $_[0]->numify
   } else {
      my $hex = substr $_[0]->as_hex, 2;
      $hex = "0$hex" if 1 & length $hex; # sigh
      tag $_[0] >= 0 ? 2 : 3, pack "H*", $hex
   }
}

sub Math::BigFloat::TO_CBOR {
   my ($m, $e) = $_[0]->parts;
   tag 4, [$e->numify, $m]
}

sub Time::Piece::TO_CBOR {
   tag 1, 0 + $_[0]->epoch
}

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

