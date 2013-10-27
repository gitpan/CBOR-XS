#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <float.h>

#include "ecb.h"

// known tags
enum cbor_tag
{
   // inofficial extensions (pending iana registration)
   CBOR_TAG_PERL_OBJECT    = 256,
   CBOR_TAG_GENERIC_OBJECT = 257,

   // rfc7049
   CBOR_TAG_DATETIME    =     0, // rfc4287, utf-8
   CBOR_TAG_TIMESTAMP   =     1, // unix timestamp, any
   CBOR_TAG_POS_BIGNUM  =     2, // byte string
   CBOR_TAG_NEG_BIGNUM  =     3, // byte string
   CBOR_TAG_DECIMAL     =     4, // decimal fraction, array
   CBOR_TAG_BIGFLOAT    =     5, // array

   CBOR_TAG_CONV_B64U   =    21, // base64url, any
   CBOR_TAG_CONV_B64    =    22, // base64, any
   CBOR_TAG_CONV_HEX    =    23, // base16, any
   CBOR_TAG_CBOR        =    24, // embedded cbor, byte string

   CBOR_TAG_URI         =    32, // URI rfc3986, utf-8
   CBOR_TAG_B64U        =    33, // base64url rfc4648, utf-8
   CBOR_TAG_B64         =    34, // base6 rfc46484, utf-8
   CBOR_TAG_REGEX       =    35, // regex pcre/ecma262, utf-8
   CBOR_TAG_MIME        =    36, // mime message rfc2045, utf-8

   CBOR_TAG_MAGIC       = 55799  // self-describe cbor
};

#define F_SHRINK         0x00000200UL
#define F_ALLOW_UNKNOWN  0x00002000UL

#define INIT_SIZE   32 // initial scalar size to be allocated

#define SB do {
#define SE } while (0)

#define IN_RANGE_INC(type,val,beg,end) \
  ((unsigned type)((unsigned type)(val) - (unsigned type)(beg)) \
  <= (unsigned type)((unsigned type)(end) - (unsigned type)(beg)))

#define ERR_NESTING_EXCEEDED "cbor text or perl structure exceeds maximum nesting level (max_depth set too low?)"

#ifdef USE_ITHREADS
# define CBOR_SLOW 1
# define CBOR_STASH (cbor_stash ? cbor_stash : gv_stashpv ("CBOR::XS", 1))
#else
# define CBOR_SLOW 0
# define CBOR_STASH cbor_stash
#endif

static HV *cbor_stash, *types_boolean_stash, *types_error_stash, *cbor_tagged_stash; // CBOR::XS::
static SV *types_true, *types_false, *types_error, *sv_cbor;

typedef struct {
  U32 flags;
  U32 max_depth;
  STRLEN max_size;
} CBOR;

ecb_inline void
cbor_init (CBOR *cbor)
{
  Zero (cbor, 1, CBOR);
  cbor->max_depth = 512;
}

/////////////////////////////////////////////////////////////////////////////
// utility functions

ecb_inline SV *
get_bool (const char *name)
{
  SV *sv = get_sv (name, 1);

  SvREADONLY_on (sv);
  SvREADONLY_on (SvRV (sv));

  return sv;
}

ecb_inline void
shrink (SV *sv)
{
  sv_utf8_downgrade (sv, 1);

  if (SvLEN (sv) > SvCUR (sv) + 1)
    {
#ifdef SvPV_shrink_to_cur
      SvPV_shrink_to_cur (sv);
#elif defined (SvPV_renew)
      SvPV_renew (sv, SvCUR (sv) + 1);
#endif
    }
}

/////////////////////////////////////////////////////////////////////////////
// fp hell

//TODO

/////////////////////////////////////////////////////////////////////////////
// encoder

// structure used for encoding CBOR
typedef struct
{
  char *cur;  // SvPVX (sv) + current output position
  char *end;  // SvEND (sv)
  SV *sv;     // result scalar
  CBOR cbor;
  U32 depth;  // recursion level
} enc_t;

ecb_inline void
need (enc_t *enc, STRLEN len)
{
  if (ecb_expect_false (enc->cur + len >= enc->end))
    {
      STRLEN cur = enc->cur - (char *)SvPVX (enc->sv);
      SvGROW (enc->sv, cur + (len < (cur >> 2) ? cur >> 2 : len) + 1);
      enc->cur = SvPVX (enc->sv) + cur;
      enc->end = SvPVX (enc->sv) + SvLEN (enc->sv) - 1;
    }
}

ecb_inline void
encode_ch (enc_t *enc, char ch)
{
  need (enc, 1);
  *enc->cur++ = ch;
}

static void
encode_uint (enc_t *enc, int major, UV len)
{
   need (enc, 9);

   if (len < 24)
      *enc->cur++ = major | len;
   else if (len <= 0xff)
     {
       *enc->cur++ = major | 24;
       *enc->cur++ = len;
     }
   else if (len <= 0xffff)
     {
       *enc->cur++ = major | 25;
       *enc->cur++ = len >> 8;
       *enc->cur++ = len;
     }
   else if (len <= 0xffffffff)
     {
       *enc->cur++ = major | 26;
       *enc->cur++ = len >> 24;
       *enc->cur++ = len >> 16;
       *enc->cur++ = len >>  8;
       *enc->cur++ = len;
     }
   else
     {
       *enc->cur++ = major | 27;
       *enc->cur++ = len >> 56;
       *enc->cur++ = len >> 48;
       *enc->cur++ = len >> 40;
       *enc->cur++ = len >> 32;
       *enc->cur++ = len >> 24;
       *enc->cur++ = len >> 16;
       *enc->cur++ = len >>  8;
       *enc->cur++ = len;
     }
}

static void
encode_str (enc_t *enc, int utf8, char *str, STRLEN len)
{
  encode_uint (enc, utf8 ? 0x60 : 0x40, len);
  need (enc, len);
  memcpy (enc->cur, str, len);
  enc->cur += len;
}

static void encode_sv (enc_t *enc, SV *sv);

static void
encode_av (enc_t *enc, AV *av)
{
  int i, len = av_len (av);

  if (enc->depth >= enc->cbor.max_depth)
    croak (ERR_NESTING_EXCEEDED);

  ++enc->depth;

  encode_uint (enc, 0x80, len + 1);

  for (i = 0; i <= len; ++i)
    {
      SV **svp = av_fetch (av, i, 0);
      encode_sv (enc, svp ? *svp : &PL_sv_undef);
    }

  --enc->depth;
}

static void
encode_hv (enc_t *enc, HV *hv)
{
  HE *he;

  if (enc->depth >= enc->cbor.max_depth)
    croak (ERR_NESTING_EXCEEDED);

  ++enc->depth;

  int pairs = hv_iterinit (hv);
  int mg = SvMAGICAL (hv);

  if (mg)
    encode_ch (enc, 0xa0 | 31);
  else
    encode_uint (enc, 0xa0, pairs);

  while ((he = hv_iternext (hv)))
    {
      if (HeKLEN (he) == HEf_SVKEY)
        encode_sv (enc, HeSVKEY (he));
      else
        encode_str (enc, HeKUTF8 (he), HeKEY (he), HeKLEN (he));

      encode_sv (enc, ecb_expect_false (mg) ? hv_iterval (hv, he) : HeVAL (he));
    }

  if (mg)
    encode_ch (enc, 0xe0 | 31);

  --enc->depth;
}

// encode objects, arrays and special \0=false and \1=true values.
static void
encode_rv (enc_t *enc, SV *sv)
{
  svtype svt;

  SvGETMAGIC (sv);
  svt = SvTYPE (sv);

  if (ecb_expect_false (SvOBJECT (sv)))
    {
      HV *boolean_stash = !CBOR_SLOW || types_boolean_stash
                          ? types_boolean_stash
                          : gv_stashpv ("Types::Serialiser::Boolean", 1);
      HV *error_stash   = !CBOR_SLOW || types_error_stash
                          ? types_error_stash
                          : gv_stashpv ("Types::Serialiser::Error", 1);
      HV *tagged_stash  = !CBOR_SLOW || cbor_tagged_stash
                          ? cbor_tagged_stash
                          : gv_stashpv ("CBOR::XS::Tagged" , 1);

      HV *stash = SvSTASH (sv);
      GV *method;

      if (stash == boolean_stash)
        encode_ch (enc, SvIV (sv) ? 0xe0 | 21 : 0xe0 | 20);
      else if (stash == error_stash)
        encode_ch (enc, 0xe0 | 23);
      else if (stash == tagged_stash)
        {
          if (svt != SVt_PVAV)
            croak ("encountered CBOR::XS::Tagged object that isn't an array");

          encode_uint (enc, 0xc0, SvUV (*av_fetch ((AV *)sv, 0, 1)));
          encode_sv (enc, *av_fetch ((AV *)sv, 1, 1));
        }
      else if ((method = gv_fetchmethod_autoload (stash, "TO_CBOR", 0)))
        {
          dSP;

          ENTER; SAVETMPS; PUSHMARK (SP);
          // we re-bless the reference to get overload and other niceties right
          XPUSHs (sv_bless (sv_2mortal (newRV_inc (sv)), stash));

          PUTBACK;
          // G_SCALAR ensures that return value is 1
          call_sv ((SV *)GvCV (method), G_SCALAR);
          SPAGAIN;

          // catch this surprisingly common error
          if (SvROK (TOPs) && SvRV (TOPs) == sv)
            croak ("%s::TO_CBOR method returned same object as was passed instead of a new one", HvNAME (stash));

          encode_sv (enc, POPs);

          PUTBACK;

          FREETMPS; LEAVE;
        }
      else if ((method = gv_fetchmethod_autoload (stash, "FREEZE", 0)) != 0)
        {
          dSP;

          ENTER; SAVETMPS; PUSHMARK (SP);
          EXTEND (SP, 2);
          // we re-bless the reference to get overload and other niceties right
          PUSHs (sv_bless (sv_2mortal (newRV_inc (sv)), stash));
          PUSHs (sv_cbor);

          PUTBACK;
          int count = call_sv ((SV *)GvCV (method), G_ARRAY);
          SPAGAIN;

          // catch this surprisingly common error
          if (count == 1 && SvROK (TOPs) && SvRV (TOPs) == sv)
            croak ("%s::FREEZE(CBOR) method returned same object as was passed instead of a new one", HvNAME (stash));

          encode_uint (enc, 0xc0, CBOR_TAG_PERL_OBJECT);
          encode_uint (enc, 0x80, count + 1);
          encode_str (enc, HvNAMEUTF8 (stash), HvNAME (stash), HvNAMELEN (stash));

          while (count)
            encode_sv (enc, SP[1 - count--]);

          PUTBACK;

          FREETMPS; LEAVE;
        }
      else
        croak ("encountered object '%s', but no TO_CBOR or FREEZE methods available on it",
               SvPV_nolen (sv_2mortal (newRV_inc (sv))));
    }
  else if (svt == SVt_PVHV)
    encode_hv (enc, (HV *)sv);
  else if (svt == SVt_PVAV)
    encode_av (enc, (AV *)sv);
  else if (svt < SVt_PVAV)
    {
      STRLEN len = 0;
      char *pv = svt ? SvPV (sv, len) : 0;

      if (len == 1 && *pv == '1')
        encode_ch (enc, 0xe0 | 21);
      else if (len == 1 && *pv == '0')
        encode_ch (enc, 0xe0 | 20);
      else if (enc->cbor.flags & F_ALLOW_UNKNOWN)
        encode_ch (enc, 0xe0 | 23);
      else
        croak ("cannot encode reference to scalar '%s' unless the scalar is 0 or 1",
               SvPV_nolen (sv_2mortal (newRV_inc (sv))));
    }
  else if (enc->cbor.flags & F_ALLOW_UNKNOWN)
    encode_ch (enc, 0xe0 | 23);
  else
    croak ("encountered %s, but CBOR can only represent references to arrays or hashes",
           SvPV_nolen (sv_2mortal (newRV_inc (sv))));
}

static void
encode_nv (enc_t *enc, SV *sv)
{
  double nv = SvNVX (sv);

  need (enc, 9);

  if (ecb_expect_false (nv == (U32)nv))
    encode_uint (enc, 0x00, (U32)nv);
  //TODO: maybe I32?
  else if (ecb_expect_false (nv == (float)nv))
    {
      uint32_t fp = ecb_float_to_binary32 (nv);

      *enc->cur++ = 0xe0 | 26;

      if (!ecb_big_endian ())
        fp = ecb_bswap32 (fp);

      memcpy (enc->cur, &fp, 4);
      enc->cur += 4;
    }
  else
    {
      uint64_t fp = ecb_double_to_binary64 (nv);

      *enc->cur++ = 0xe0 | 27;

      if (!ecb_big_endian ())
        fp = ecb_bswap64 (fp);

      memcpy (enc->cur, &fp, 8);
      enc->cur += 8;
    }
}

static void
encode_sv (enc_t *enc, SV *sv)
{
  SvGETMAGIC (sv);

  if (SvPOKp (sv))
    {
      STRLEN len;
      char *str = SvPV (sv, len);
      encode_str (enc, SvUTF8 (sv), str, len);
    }
  else if (SvNOKp (sv))
    encode_nv (enc, sv);
  else if (SvIOKp (sv))
    {
      if (SvIsUV (sv))
        encode_uint (enc, 0x00, SvUVX (sv));
      else if (SvIVX (sv) >= 0)
        encode_uint (enc, 0x00, SvIVX (sv));
      else
        encode_uint (enc, 0x20, -(SvIVX (sv) + 1));
    }
  else if (SvROK (sv))
    encode_rv (enc, SvRV (sv));
  else if (!SvOK (sv))
    encode_ch (enc, 0xe0 | 22);
  else if (enc->cbor.flags & F_ALLOW_UNKNOWN)
    encode_ch (enc, 0xe0 | 23);
  else
    croak ("encountered perl type (%s,0x%x) that CBOR cannot handle, check your input data",
           SvPV_nolen (sv), (unsigned int)SvFLAGS (sv));
}

static SV *
encode_cbor (SV *scalar, CBOR *cbor)
{
  enc_t enc;

  enc.cbor      = *cbor;
  enc.sv        = sv_2mortal (NEWSV (0, INIT_SIZE));
  enc.cur       = SvPVX (enc.sv);
  enc.end       = SvEND (enc.sv);
  enc.depth     = 0;

  SvPOK_only (enc.sv);
  encode_sv (&enc, scalar);

  SvCUR_set (enc.sv, enc.cur - SvPVX (enc.sv));
  *SvEND (enc.sv) = 0; // many xs functions expect a trailing 0 for text strings

  if (enc.cbor.flags & F_SHRINK)
    shrink (enc.sv);

  return enc.sv;
}

/////////////////////////////////////////////////////////////////////////////
// decoder

// structure used for decoding CBOR
typedef struct
{
  U8 *cur; // current parser pointer
  U8 *end; // end of input string
  const char *err; // parse error, if != 0
  CBOR cbor;
  U32 depth; // recursion depth
  U32 maxdepth; // recursion depth limit
} dec_t;

#define ERR(reason) SB if (!dec->err) dec->err = reason; goto fail; SE

#define WANT(len) if (ecb_expect_false (dec->cur + len > dec->end)) ERR ("unexpected end of CBOR data")

#define DEC_INC_DEPTH if (++dec->depth > dec->cbor.max_depth) ERR (ERR_NESTING_EXCEEDED)
#define DEC_DEC_DEPTH --dec->depth

static UV
decode_uint (dec_t *dec)
{
  switch (*dec->cur & 31)
    {
      case  0: case  1: case  2: case  3: case  4: case  5: case  6: case  7:
      case  8: case  9: case 10: case 11: case 12: case 13: case 14: case 15:
      case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
        return *dec->cur++ & 31;

      case 24:
        WANT (2);
        dec->cur += 2;
        return dec->cur[-1];

      case 25:
        WANT (3);
        dec->cur += 3;
        return (((UV)dec->cur[-2]) <<  8)
             |  ((UV)dec->cur[-1]);

      case 26:
        WANT (5);
        dec->cur += 5;
        return (((UV)dec->cur[-4]) << 24)
             | (((UV)dec->cur[-3]) << 16)
             | (((UV)dec->cur[-2]) <<  8)
             |  ((UV)dec->cur[-1]);

      case 27:
        WANT (9);
        dec->cur += 9;
        return (((UV)dec->cur[-8]) << 56)
             | (((UV)dec->cur[-7]) << 48)
             | (((UV)dec->cur[-6]) << 40)
             | (((UV)dec->cur[-5]) << 32)
             | (((UV)dec->cur[-4]) << 24)
             | (((UV)dec->cur[-3]) << 16)
             | (((UV)dec->cur[-2]) <<  8)
             |  ((UV)dec->cur[-1]);

      default:
        ERR ("corrupted CBOR data (unsupported integer minor encoding)");
    }

fail:
  return 0;
}

static SV *decode_sv (dec_t *dec);

static SV *
decode_av (dec_t *dec)
{
  AV *av = newAV ();

  DEC_INC_DEPTH;

  if ((*dec->cur & 31) == 31)
    {
      ++dec->cur;

      for (;;)
        {
          WANT (1);

          if (*dec->cur == (0xe0 | 31))
            {
              ++dec->cur;
              break;
            }

          av_push (av, decode_sv (dec));
        }
    }
  else
    {
      int i, len = decode_uint (dec);

      av_fill (av, len - 1);

      for (i = 0; i < len; ++i)
        AvARRAY (av)[i] = decode_sv (dec);
    }

  DEC_DEC_DEPTH;
  return newRV_noinc ((SV *)av);

fail:
  SvREFCNT_dec (av);
  DEC_DEC_DEPTH;
  return &PL_sv_undef;
}

static SV *
decode_hv (dec_t *dec)
{
  HV *hv = newHV ();

  DEC_INC_DEPTH;

  if ((*dec->cur & 31) == 31)
    {
      ++dec->cur;

      for (;;)
        {
          WANT (1);

          if (*dec->cur == (0xe0 | 31))
            {
              ++dec->cur;
              break;
            }

          SV *k = decode_sv (dec);
          SV *v = decode_sv (dec);

          hv_store_ent (hv, k, v, 0);
        }
    }
  else
    {
      int len = decode_uint (dec);

      while (len--)
        {
          SV *k = decode_sv (dec);
          SV *v = decode_sv (dec);

          hv_store_ent (hv, k, v, 0);
        }
    }

  DEC_DEC_DEPTH;
  return newRV_noinc ((SV *)hv);

fail:
  SvREFCNT_dec (hv);
  DEC_DEC_DEPTH;
  return &PL_sv_undef;
}

static SV *
decode_str (dec_t *dec, int utf8)
{
  SV *sv = 0;

  if ((*dec->cur & 31) == 31)
    {
      ++dec->cur;

      sv = newSVpvn ("", 0);

      // not very fast, and certainly not robust against illegal input
      for (;;)
        {
          WANT (1);

          if (*dec->cur == (0xe0 | 31))
            {
              ++dec->cur;
              break;
            }

          sv_catsv (sv, decode_sv (dec));
        }
    }
  else
    {
      STRLEN len = decode_uint (dec);

      WANT (len);
      sv = newSVpvn (dec->cur, len);
      dec->cur += len;
    }

  if (utf8)
    SvUTF8_on (sv);

  return sv;

fail:
  SvREFCNT_dec (sv);
  return &PL_sv_undef;
}

static SV *
decode_tagged (dec_t *dec)
{
  UV tag = decode_uint (dec);
  SV *sv = decode_sv (dec);

  if (tag == CBOR_TAG_MAGIC)
    return sv;
  else if (tag == CBOR_TAG_PERL_OBJECT)
    {
      if (!SvROK (sv) || SvTYPE (SvRV (sv)) != SVt_PVAV)
        ERR ("corrupted CBOR data (non-array perl object)");

      AV *av = (AV *)SvRV (sv);
      int len = av_len (av) + 1;
      HV *stash = gv_stashsv (*av_fetch (av, 0, 1), 0);

      if (!stash)
        ERR ("cannot decode perl-object (package does not exist)");

      GV *method = gv_fetchmethod_autoload (stash, "THAW", 0);
      
      if (!method)
        ERR ("cannot decode perl-object (package does not have a THAW method)");
      
      dSP;

      ENTER; SAVETMPS; PUSHMARK (SP);
      EXTEND (SP, len + 1);
      // we re-bless the reference to get overload and other niceties right
      PUSHs (*av_fetch (av, 0, 1));
      PUSHs (sv_cbor);

      int i;

      for (i = 1; i < len; ++i)
        PUSHs (*av_fetch (av, i, 1));

      PUTBACK;
      call_sv ((SV *)GvCV (method), G_SCALAR);
      SPAGAIN;

      sv = SvREFCNT_inc (POPs);

      PUTBACK;

      FREETMPS; LEAVE;

      return sv;
    }
  else
    {
      AV *av = newAV ();
      av_push (av, newSVuv (tag));
      av_push (av, sv);

      HV *tagged_stash  = !CBOR_SLOW || cbor_tagged_stash
                          ? cbor_tagged_stash
                          : gv_stashpv ("CBOR::XS::Tagged" , 1);

      return sv_bless (newRV_noinc ((SV *)av), tagged_stash);
    }

fail:
  SvREFCNT_dec (sv);
  return &PL_sv_undef;
}

static SV *
decode_sv (dec_t *dec)
{
  WANT (1);

  switch (*dec->cur >> 5)
    {
      case 0: // unsigned int
        return newSVuv (decode_uint (dec));
      case 1: // negative int
        return newSViv (-1 - (IV)decode_uint (dec));
      case 2: // octet string
        return decode_str (dec, 0);
      case 3: // utf-8 string
        return decode_str (dec, 1);
      case 4: // array
        return decode_av (dec);
      case 5: // map
        return decode_hv (dec);
      case 6: // tag
        return decode_tagged (dec);
      case 7: // misc
        switch (*dec->cur++ & 31)
          {
            case 20:
#if CBOR_SLOW
              types_false = get_bool ("Types::Serialiser::false");
#endif
              return newSVsv (types_false);
            case 21:
#if CBOR_SLOW
              types_true = get_bool ("Types::Serialiser::true");
#endif
              return newSVsv (types_true);
            case 22:
              return newSVsv (&PL_sv_undef);
            case 23:
#if CBOR_SLOW
              types_error = get_bool ("Types::Serialiser::error");
#endif
              return newSVsv (types_error);

            case 25:
              {
                WANT (2);

                uint16_t fp = (dec->cur[0] << 8) | dec->cur[1];
                dec->cur += 2;

                return newSVnv (ecb_binary16_to_float (fp));
              }

            case 26:
              {
                uint32_t fp;
                WANT (4);
                memcpy (&fp, dec->cur, 4);
                dec->cur += 4;

                if (!ecb_big_endian ())
                  fp = ecb_bswap32 (fp);

                return newSVnv (ecb_binary32_to_float (fp));
              }

            case 27:
              {
                uint64_t fp;
                WANT (8);
                memcpy (&fp, dec->cur, 8);
                dec->cur += 8;

                if (!ecb_big_endian ())
                  fp = ecb_bswap64 (fp);

                return newSVnv (ecb_binary64_to_double (fp));
              }

            // 0..19 unassigned
            // 24 reserved + unassigned (reserved values are not encodable)
            default:
              ERR ("corrupted CBOR data (reserved/unassigned major 7 value)");
          }

        break;
  }

fail:
  return &PL_sv_undef;
}

static SV *
decode_cbor (SV *string, CBOR *cbor, char **offset_return)
{
  dec_t dec;
  SV *sv;

  /* work around bugs in 5.10 where manipulating magic values
   * makes perl ignore the magic in subsequent accesses.
   * also make a copy of non-PV values, to get them into a clean
   * state (SvPV should do that, but it's buggy, see below).
   */
  /*SvGETMAGIC (string);*/
  if (SvMAGICAL (string) || !SvPOK (string))
    string = sv_2mortal (newSVsv (string));

  SvUPGRADE (string, SVt_PV);

  /* work around a bug in perl 5.10, which causes SvCUR to fail an
   * assertion with -DDEBUGGING, although SvCUR is documented to
   * return the xpv_cur field which certainly exists after upgrading.
   * according to nicholas clark, calling SvPOK fixes this.
   * But it doesn't fix it, so try another workaround, call SvPV_nolen
   * and hope for the best.
   * Damnit, SvPV_nolen still trips over yet another assertion. This
   * assertion business is seriously broken, try yet another workaround
   * for the broken -DDEBUGGING.
   */
  {
#ifdef DEBUGGING
    STRLEN offset = SvOK (string) ? sv_len (string) : 0;
#else
    STRLEN offset = SvCUR (string);
#endif

    if (offset > cbor->max_size && cbor->max_size)
      croak ("attempted decode of CBOR text of %lu bytes size, but max_size is set to %lu",
             (unsigned long)SvCUR (string), (unsigned long)cbor->max_size);
  }

  sv_utf8_downgrade (string, 0);

  dec.cbor  = *cbor;
  dec.cur   = (U8 *)SvPVX (string);
  dec.end   = (U8 *)SvEND (string);
  dec.err   = 0;
  dec.depth = 0;

  sv = decode_sv (&dec);

  if (offset_return)
    *offset_return = dec.cur;

  if (!(offset_return || !sv))
    if (dec.cur != dec.end && !dec.err)
      dec.err = "garbage after CBOR object";

  if (dec.err)
    {
      SvREFCNT_dec (sv);
      croak ("%s, at offset %d (octet 0x%02x)", dec.err, dec.cur - (U8 *)SvPVX (string), (int)(uint8_t)*dec.cur);
    }

  sv = sv_2mortal (sv);

  return sv;
}

/////////////////////////////////////////////////////////////////////////////
// XS interface functions

MODULE = CBOR::XS		PACKAGE = CBOR::XS

BOOT:
{
	cbor_stash         = gv_stashpv ("CBOR::XS"         , 1);
	cbor_tagged_stash  = gv_stashpv ("CBOR::XS::Tagged" , 1);

	types_boolean_stash = gv_stashpv ("Types::Serialiser::Boolean", 1);
	types_error_stash   = gv_stashpv ("Types::Serialiser::Error"  , 1);

        types_true  = get_bool ("Types::Serialiser::true" );
        types_false = get_bool ("Types::Serialiser::false");
        types_error = get_bool ("Types::Serialiser::error");

        sv_cbor = newSVpv ("CBOR", 0);
        SvREADONLY_on (sv_cbor);
}

PROTOTYPES: DISABLE

void CLONE (...)
	CODE:
        cbor_stash          = 0;
        cbor_tagged_stash   = 0;
        types_error_stash   = 0;
        types_boolean_stash = 0;

void new (char *klass)
	PPCODE:
{
	SV *pv = NEWSV (0, sizeof (CBOR));
        SvPOK_only (pv);
        cbor_init ((CBOR *)SvPVX (pv));
        XPUSHs (sv_2mortal (sv_bless (
           newRV_noinc (pv),
           strEQ (klass, "CBOR::XS") ? CBOR_STASH : gv_stashpv (klass, 1)
        )));
}

void shrink (CBOR *self, int enable = 1)
	ALIAS:
        shrink          = F_SHRINK
        allow_unknown   = F_ALLOW_UNKNOWN
	PPCODE:
{
        if (enable)
          self->flags |=  ix;
        else
          self->flags &= ~ix;

        XPUSHs (ST (0));
}

void get_shrink (CBOR *self)
	ALIAS:
        get_shrink          = F_SHRINK
        get_allow_unknown   = F_ALLOW_UNKNOWN
	PPCODE:
        XPUSHs (boolSV (self->flags & ix));

void max_depth (CBOR *self, U32 max_depth = 0x80000000UL)
	PPCODE:
        self->max_depth = max_depth;
        XPUSHs (ST (0));

U32 get_max_depth (CBOR *self)
	CODE:
        RETVAL = self->max_depth;
	OUTPUT:
        RETVAL

void max_size (CBOR *self, U32 max_size = 0)
	PPCODE:
        self->max_size = max_size;
        XPUSHs (ST (0));

int get_max_size (CBOR *self)
	CODE:
        RETVAL = self->max_size;
	OUTPUT:
        RETVAL

#if 0 //TODO

void filter_cbor_object (CBOR *self, SV *cb = &PL_sv_undef)
	PPCODE:
{
        SvREFCNT_dec (self->cb_object);
        self->cb_object = SvOK (cb) ? newSVsv (cb) : 0;

        XPUSHs (ST (0));
}

void filter_cbor_single_key_object (CBOR *self, SV *key, SV *cb = &PL_sv_undef)
	PPCODE:
{
	if (!self->cb_sk_object)
          self->cb_sk_object = newHV ();

        if (SvOK (cb))
          hv_store_ent (self->cb_sk_object, key, newSVsv (cb), 0);
        else
          {
            hv_delete_ent (self->cb_sk_object, key, G_DISCARD, 0);

            if (!HvKEYS (self->cb_sk_object))
              {
                SvREFCNT_dec (self->cb_sk_object);
                self->cb_sk_object = 0;
              }
          }

        XPUSHs (ST (0));
}

#endif

void encode (CBOR *self, SV *scalar)
	PPCODE:
        PUTBACK; scalar = encode_cbor (scalar, self); SPAGAIN;
        XPUSHs (scalar);

void decode (CBOR *self, SV *cborstr)
	PPCODE:
        PUTBACK; cborstr = decode_cbor (cborstr, self, 0); SPAGAIN;
        XPUSHs (cborstr);

void decode_prefix (CBOR *self, SV *cborstr)
	PPCODE:
{
	SV *sv;
        char *offset;
        PUTBACK; sv = decode_cbor (cborstr, self, &offset); SPAGAIN;
        EXTEND (SP, 2);
        PUSHs (sv);
        PUSHs (sv_2mortal (newSVuv (offset - SvPVX (cborstr))));
}

#if 0

void DESTROY (CBOR *self)
	CODE:
        SvREFCNT_dec (self->cb_sk_object);
        SvREFCNT_dec (self->cb_object);

#endif

PROTOTYPES: ENABLE

void encode_cbor (SV *scalar)
	PPCODE:
{
        CBOR cbor;
        cbor_init (&cbor);
        PUTBACK; scalar = encode_cbor (scalar, &cbor); SPAGAIN;
        XPUSHs (scalar);
}

void decode_cbor (SV *cborstr)
	PPCODE:
{
        CBOR cbor;
        cbor_init (&cbor);
        PUTBACK; cborstr = decode_cbor (cborstr, &cbor, 0); SPAGAIN;
        XPUSHs (cborstr);
}

