/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlscertificate-apple.c
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include "glib.h"

#include <string.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CoreFoundation/CoreFoundation.h>

#include "gtlscertificate-apple.h"

#include <glib/gi18n-lib.h>

#ifndef GIO_APPLE_PUBLIC_API_ONLY
/*
 * Not declared in Security/SecItem.h, but exported from
 * Security.framework since macOS 14 / iOS 17. SecKeyCreateWithData
 * accepts the raw 32-byte seed as the private-key payload and the raw
 * 32-byte point as the public-key payload.
 */
extern const CFStringRef kSecAttrKeyTypeEd25519
    API_AVAILABLE(macos(14.0), ios(17.0), tvos(17.0), watchos(10.0));
#endif

struct _GTlsCertificateApple
{
  GTlsCertificate parent_instance;

  SecCertificateRef cert;
  SecKeyRef         private_key;
  SecIdentityRef    identity;

  GTlsCertificateApple *issuer;

  GByteArray *pkcs12_data;
  gchar      *password;

  GError *construct_error;

  guint have_cert : 1;
  guint have_key  : 1;
};

enum
{
  PROP_0,
  PROP_CERTIFICATE,
  PROP_CERTIFICATE_PEM,
  PROP_PRIVATE_KEY,
  PROP_PRIVATE_KEY_PEM,
  PROP_ISSUER,
  PROP_NOT_VALID_BEFORE,
  PROP_NOT_VALID_AFTER,
  PROP_SUBJECT_NAME,
  PROP_ISSUER_NAME,
  PROP_DNS_NAMES,
  PROP_IP_ADDRESSES,
  PROP_PKCS12_DATA,
  PROP_PASSWORD,
};

typedef enum {
  PKCS8_ALGO_UNKNOWN,
  PKCS8_ALGO_RSA,
  PKCS8_ALGO_EC,
  PKCS8_ALGO_ED25519,
} Pkcs8Algo;

typedef struct {
  const guint8 *data;
  gsize         len;
} DerSlice;

static const guint8 OID_RSA_ENCRYPTION[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const guint8 OID_EC_PUBLIC_KEY[]  = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const guint8 OID_ED25519[]        = { 0x2b, 0x65, 0x70 };

static void                 g_tls_certificate_apple_dispose        (GObject *object);
static void                 g_tls_certificate_apple_finalize       (GObject *object);
static void                 g_tls_certificate_apple_set_property   (GObject      *object,
                                                                    guint         prop_id,
                                                                    const GValue *value,
                                                                    GParamSpec   *pspec);
static void                 g_tls_certificate_apple_get_property   (GObject    *object,
                                                                    guint       prop_id,
                                                                    GValue     *value,
                                                                    GParamSpec *pspec);
static GTlsCertificateFlags g_tls_certificate_apple_verify         (GTlsCertificate     *cert,
                                                                    GSocketConnectable  *identity,
                                                                    GTlsCertificate     *trusted_ca);
static void                 g_tls_certificate_apple_initable_iface_init (GInitableIface *iface);
static gboolean             g_tls_certificate_apple_initable_init  (GInitable     *initable,
                                                                    GCancellable  *cancellable,
                                                                    GError       **error);

static SecCertificateRef cert_from_der                (const guchar *der,
                                                       gsize         len);
static guchar           *pem_decode_block             (const gchar *pem,
                                                       gssize       pem_len,
                                                       const gchar *label,
                                                       gsize       *out_len);
static SecKeyRef         key_from_der                 (const guint8 *der,
                                                       gsize         len,
                                                       const gchar  *pem_label);
static SecKeyRef         key_from_rsa_pkcs1           (const guint8 *der,
                                                       gsize         len);
static SecKeyRef         key_from_ec_sec1             (const guint8 *der,
                                                       gsize         len);
#ifndef GIO_APPLE_PUBLIC_API_ONLY
static SecKeyRef         key_from_ed25519_curve       (const guint8 *der,
                                                       gsize         len);
#endif
static Pkcs8Algo         extract_pkcs8_private_key    (const guint8  *der,
                                                       gsize          len,
                                                       const guint8 **out_inner,
                                                       gsize         *out_inner_len);
static gboolean          asn1_read_tlv                (const guint8  *der,
                                                       gsize          len,
                                                       guint8        *out_tag,
                                                       const guint8 **out_content,
                                                       gsize         *out_content_len,
                                                       gsize         *out_total_len);

static gchar            *cert_to_pem                  (SecCertificateRef cert);
static GByteArray       *export_private_key_pkcs8     (SecKeyRef key);
static GByteArray       *build_pkcs8_rsa              (const guint8 *pkcs1,
                                                       gsize         len);
static GByteArray       *build_pkcs8_ec               (const guint8 *x963,
                                                       gsize         x963_len,
                                                       gint          key_size_bits);
static GByteArray       *build_pkcs8_ed25519          (const guint8 *seed,
                                                       gsize         seed_len);
static void              der_append_tlv               (GByteArray   *out,
                                                       guint8        tag,
                                                       const guint8 *value,
                                                       gsize         length);
static void              der_append_length            (GByteArray *out,
                                                       gsize       length);
static void              der_append_sequence          (GByteArray   *out,
                                                       const guint8 *content,
                                                       gsize         content_len);
static void              der_append_integer_uint      (GByteArray *out,
                                                       guint64     value);
static void              der_append_null              (GByteArray *out);
static void              der_append_oid               (GByteArray   *out,
                                                       const guint8 *oid,
                                                       gsize         length);
static void              der_append_octet_string      (GByteArray   *out,
                                                       const guint8 *bytes,
                                                       gsize         length);
static gchar            *pem_encode_der               (const gchar  *label,
                                                       const guint8 *der,
                                                       gsize         der_len);
static GDateTime        *certificate_validity_date    (SecCertificateRef cert,
                                                       gboolean          want_not_after);
static gchar            *certificate_subject_name     (SecCertificateRef cert);
static gchar            *certificate_issuer_name      (SecCertificateRef cert);
static gchar            *x500_name_to_string          (const guint8 *der,
                                                       gsize         len);
static GPtrArray        *certificate_san_dns_names    (SecCertificateRef cert);
static GPtrArray        *certificate_san_ip_addresses (SecCertificateRef cert);
static gboolean          find_subject_alt_name_der    (SecCertificateRef cert,
                                                       guint8         **out_value,
                                                       gsize           *out_value_len);
static void              collect_general_names        (const guint8 *der,
                                                       gsize         len,
                                                       GPtrArray    *out_dns,
                                                       GPtrArray    *out_ip);

static gboolean          certificate_is_not_yet_valid (GTlsCertificate *cert);

static gboolean          import_pkcs12                (GTlsCertificateApple  *self,
                                                       GError               **error);
static void              chain_extra_certs_from_pkcs12 (GTlsCertificateApple *self,
                                                        CFArrayRef            items);
static gboolean          import_pkcs12_plain          (GTlsCertificateApple *self);
static gboolean          parse_pkcs7_data_body        (const guint8  *der,
                                                       gsize          len,
                                                       gsize         *out_total,
                                                       const guint8 **out_body,
                                                       gsize         *out_body_len);

static SecIdentityRef    synthesize_identity          (SecCertificateRef cert,
                                                       SecKeyRef         key);
static GByteArray       *build_pkcs12                 (SecCertificateRef cert,
                                                       SecKeyRef         key,
                                                       const gchar      *password);
static GByteArray       *build_safe_bag               (const guint8 *bag_id,
                                                       gsize         bag_id_len,
                                                       const guint8 *bag_value,
                                                       gsize         bag_value_len,
                                                       const guint8 *local_key_id,
                                                       gsize         local_key_id_len);
static GByteArray       *build_pkcs12_mac_data        (const guint8 *auth_safe,
                                                       gsize         auth_safe_len,
                                                       const gchar  *password);
static GByteArray       *encrypt_pkcs8_pbes2          (const guint8 *pkcs8,
                                                       gsize         pkcs8_len,
                                                       const gchar  *password);
static void              pkcs12_kdf                   (const gchar  *password,
                                                       const guint8 *salt,
                                                       gsize         salt_len,
                                                       guint         iterations,
                                                       guint8        id,
                                                       guint8       *out,
                                                       gsize         out_len);

static CFDataRef         copy_raw_tbs_name            (SecCertificateRef cert,
                                                       gboolean          want_subject);

static gchar            *certificate_subject_cn       (SecCertificateRef cert);
static gchar            *x500_name_cn                 (const guint8 *der,
                                                       gsize         len);

G_DEFINE_TYPE_WITH_CODE (GTlsCertificateApple, g_tls_certificate_apple, G_TYPE_TLS_CERTIFICATE,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_certificate_apple_initable_iface_init))

static void
g_tls_certificate_apple_class_init (GTlsCertificateAppleClass *klass)
{
  GObjectClass *object_class      = G_OBJECT_CLASS (klass);
  GTlsCertificateClass *cert_class = G_TLS_CERTIFICATE_CLASS (klass);

  object_class->dispose      = g_tls_certificate_apple_dispose;
  object_class->finalize     = g_tls_certificate_apple_finalize;
  object_class->set_property = g_tls_certificate_apple_set_property;
  object_class->get_property = g_tls_certificate_apple_get_property;

  cert_class->verify = g_tls_certificate_apple_verify;

  g_object_class_override_property (object_class, PROP_CERTIFICATE,       "certificate");
  g_object_class_override_property (object_class, PROP_CERTIFICATE_PEM,   "certificate-pem");
  g_object_class_override_property (object_class, PROP_PRIVATE_KEY,       "private-key");
  g_object_class_override_property (object_class, PROP_PRIVATE_KEY_PEM,   "private-key-pem");
  g_object_class_override_property (object_class, PROP_ISSUER,            "issuer");
  g_object_class_override_property (object_class, PROP_NOT_VALID_BEFORE,  "not-valid-before");
  g_object_class_override_property (object_class, PROP_NOT_VALID_AFTER,   "not-valid-after");
  g_object_class_override_property (object_class, PROP_SUBJECT_NAME,      "subject-name");
  g_object_class_override_property (object_class, PROP_ISSUER_NAME,       "issuer-name");
  g_object_class_override_property (object_class, PROP_DNS_NAMES,         "dns-names");
  g_object_class_override_property (object_class, PROP_IP_ADDRESSES,      "ip-addresses");
  g_object_class_override_property (object_class, PROP_PKCS12_DATA,       "pkcs12-data");
  g_object_class_override_property (object_class, PROP_PASSWORD,          "password");
}

static void
g_tls_certificate_apple_init (GTlsCertificateApple *self)
{
}

static void
g_tls_certificate_apple_dispose (GObject *object)
{
  GTlsCertificateApple *self = G_TLS_CERTIFICATE_APPLE (object);

  g_clear_pointer (&self->pkcs12_data, g_byte_array_unref);
  g_clear_object (&self->issuer);
  g_clear_pointer (&self->identity, CFRelease);
  g_clear_pointer (&self->private_key, CFRelease);
  g_clear_pointer (&self->cert, CFRelease);

  G_OBJECT_CLASS (g_tls_certificate_apple_parent_class)->dispose (object);
}

static void
g_tls_certificate_apple_finalize (GObject *object)
{
  GTlsCertificateApple *self = G_TLS_CERTIFICATE_APPLE (object);

  g_clear_error (&self->construct_error);
  g_free (self->password);

  G_OBJECT_CLASS (g_tls_certificate_apple_parent_class)->finalize (object);
}

static void
g_tls_certificate_apple_set_property (GObject      *object,
                                      guint         prop_id,
                                      const GValue *value,
                                      GParamSpec   *pspec)
{
  GTlsCertificateApple *self = G_TLS_CERTIFICATE_APPLE (object);
  GByteArray *ba;
  const gchar *str;

  switch (prop_id)
    {
    case PROP_PASSWORD:
      g_free (self->password);
      self->password = g_value_dup_string (value);
      break;

    case PROP_PKCS12_DATA:
      g_clear_pointer (&self->pkcs12_data, g_byte_array_unref);
      self->pkcs12_data = (GByteArray *) g_value_dup_boxed (value);
      break;

    case PROP_CERTIFICATE:
      ba = g_value_get_boxed (value);
      if (ba && !self->have_cert)
        {
          self->cert = cert_from_der (ba->data, ba->len);
          if (!self->cert)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("Could not parse DER certificate"));
              break;
            }
          self->have_cert = TRUE;
        }
      break;

    case PROP_CERTIFICATE_PEM:
      str = g_value_get_string (value);
      if (str && !self->have_cert)
        {
          gsize der_len = 0;
          guchar *der = pem_decode_block (str, -1, "CERTIFICATE", &der_len);
          if (!der)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("Could not parse PEM certificate"));
              break;
            }
          self->cert = cert_from_der (der, der_len);
          g_free (der);
          if (!self->cert)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("PEM certificate payload was not valid DER"));
              break;
            }
          self->have_cert = TRUE;
        }
      break;

    case PROP_PRIVATE_KEY:
      ba = g_value_get_boxed (value);
      if (ba && !self->have_key)
        {
          self->private_key = key_from_der (ba->data, ba->len, NULL);
          if (!self->private_key)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("Could not parse DER private key"));
              break;
            }
          self->have_key = TRUE;
        }
      break;

    case PROP_PRIVATE_KEY_PEM:
      str = g_value_get_string (value);
      if (str && !self->have_key)
        {
          gsize der_len = 0;
          const gchar *label = NULL;
          guchar *der;

          if (strstr (str, "-----BEGIN RSA PRIVATE KEY-----"))
            label = "RSA PRIVATE KEY";
          else if (strstr (str, "-----BEGIN EC PRIVATE KEY-----"))
            label = "EC PRIVATE KEY";

          der = pem_decode_block (str, -1, label, &der_len);
          if (!der)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("Could not parse PEM private key"));
              break;
            }
          self->private_key = key_from_der (der, der_len, label);
          g_free (der);
          if (!self->private_key)
            {
              g_clear_error (&self->construct_error);
              g_set_error_literal (&self->construct_error,
                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                   _("PEM private-key payload was not valid DER"));
              break;
            }
          self->have_key = TRUE;
        }
      break;

    case PROP_ISSUER:
      g_clear_object (&self->issuer);
      self->issuer = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static SecCertificateRef
cert_from_der (const guchar *der, gsize len)
{
  SecCertificateRef cert;
  CFDataRef data;

  data = CFDataCreate (kCFAllocatorDefault, der, len);
  if (!data)
    return NULL;
  cert = SecCertificateCreateWithData (kCFAllocatorDefault, data);
  CFRelease (data);
  return cert;
}

static guchar *
pem_decode_block (const gchar *pem,
                  gssize       pem_len,
                  const gchar *label,
                  gsize       *out_len)
{
  guchar *der;
  gsize der_len;
  const gchar *p, *end;
  const gchar *begin_marker = NULL, *end_marker = NULL;
  gchar *stripped;
  GString *b64;
  const gchar *line, *line_end;

  if (pem_len < 0)
    pem_len = strlen (pem);
  end = pem + pem_len;

  p = pem;
  if (label)
    {
      gchar *needle = g_strdup_printf ("-----BEGIN %s-----", label);
      begin_marker = g_strstr_len (p, end - p, needle);
      g_free (needle);
      if (!begin_marker)
        return NULL;
      p = strchr (begin_marker, '\n');
      if (!p)
        return NULL;
      ++p;
      needle = g_strdup_printf ("-----END %s-----", label);
      end_marker = g_strstr_len (p, end - p, needle);
      g_free (needle);
      if (!end_marker)
        return NULL;
    }
  else
    {
      begin_marker = g_strstr_len (p, end - p, "-----BEGIN ");
      if (!begin_marker)
        return NULL;
      p = strchr (begin_marker, '\n');
      if (!p)
        return NULL;
      ++p;
      end_marker = g_strstr_len (p, end - p, "-----END ");
      if (!end_marker)
        return NULL;
    }

  b64 = g_string_new (NULL);
  line = p;
  while (line < end_marker)
    {
      line_end = memchr (line, '\n', end_marker - line);
      if (!line_end)
        line_end = end_marker;

      if (line_end > line && line_end[-1] == '\r')
        g_string_append_len (b64, line, line_end - line - 1);
      else
        g_string_append_len (b64, line, line_end - line);

      if (line_end >= end_marker)
        break;
      line = line_end + 1;
    }

  stripped = g_string_free (b64, FALSE);
  der = g_base64_decode (stripped, &der_len);
  g_free (stripped);

  if (!der || der_len == 0)
    {
      g_free (der);
      return NULL;
    }

  *out_len = der_len;
  return der;
}

static SecKeyRef
key_from_der (const guint8 *der,
              gsize         len,
              const gchar  *pem_label)
{
  const guint8 *inner = NULL;
  gsize inner_len = 0;

  if (pem_label != NULL && g_strcmp0 (pem_label, "RSA PRIVATE KEY") == 0)
    return key_from_rsa_pkcs1 (der, len);

  if (pem_label != NULL && g_strcmp0 (pem_label, "EC PRIVATE KEY") == 0)
    return key_from_ec_sec1 (der, len);

  switch (extract_pkcs8_private_key (der, len, &inner, &inner_len))
    {
    case PKCS8_ALGO_RSA:
      return key_from_rsa_pkcs1 (inner, inner_len);
    case PKCS8_ALGO_EC:
      return key_from_ec_sec1 (inner, inner_len);
    case PKCS8_ALGO_ED25519:
#ifdef GIO_APPLE_PUBLIC_API_ONLY
      return NULL;
#else
      return key_from_ed25519_curve (inner, inner_len);
#endif
    case PKCS8_ALGO_UNKNOWN:
    default:
      return key_from_rsa_pkcs1 (der, len);
    }
}

static SecKeyRef
key_from_rsa_pkcs1 (const guint8 *der,
                    gsize         len)
{
  SecKeyRef key;
  CFDataRef data;
  CFMutableDictionaryRef attrs;
  CFErrorRef cf_error = NULL;

  data = CFDataCreate (kCFAllocatorDefault, der, len);
  if (!data)
    return NULL;

  attrs = CFDictionaryCreateMutable (kCFAllocatorDefault, 2,
                                     &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue (attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
  CFDictionarySetValue (attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

  key = SecKeyCreateWithData (data, attrs, &cf_error);

  CFRelease (data);
  CFRelease (attrs);
  g_clear_pointer (&cf_error, CFRelease);

  return key;
}

static SecKeyRef
key_from_ec_sec1 (const guint8 *der,
                  gsize         len)
{
  SecKeyRef key;
  guint8 tag;
  const guint8 *body, *version, *priv_key, *child_body;
  gsize body_len, version_len, priv_len, child_len, total, consumed;
  const guint8 *public_point = NULL;
  gsize public_point_len = 0;
  GByteArray *combined;
  CFDataRef data;
  CFMutableDictionaryRef attrs;
  CFErrorRef cf_error = NULL;

  if (!asn1_read_tlv (der, len, &tag, &body, &body_len, &total) || tag != 0x30)
    return NULL;

  if (!asn1_read_tlv (body, body_len, &tag, &version, &version_len, &total) || tag != 0x02)
    return NULL;

  consumed = total;
  if (!asn1_read_tlv (body + consumed, body_len - consumed,
                      &tag, &priv_key, &priv_len, &total) || tag != 0x04)
    return NULL;
  consumed += total;

  while (consumed < body_len)
    {
      if (!asn1_read_tlv (body + consumed, body_len - consumed,
                          &tag, &child_body, &child_len, &total))
        break;
      if (tag == 0xa1)
        {
          guint8 inner_tag;
          const guint8 *inner_body;
          gsize inner_len, inner_total;
          if (asn1_read_tlv (child_body, child_len, &inner_tag, &inner_body, &inner_len, &inner_total) &&
              inner_tag == 0x03 && inner_len > 1 && inner_body[0] == 0x00)
            {
              public_point = inner_body + 1;
              public_point_len = inner_len - 1;
            }
        }
      consumed += total;
    }

  if (!public_point || public_point_len < 1 + 2 || public_point[0] != 0x04)
    return NULL;

  combined = g_byte_array_sized_new (public_point_len + priv_len);
  g_byte_array_append (combined, public_point, public_point_len);
  g_byte_array_append (combined, priv_key, priv_len);

  data = CFDataCreate (kCFAllocatorDefault, combined->data, combined->len);
  g_byte_array_free (combined, TRUE);

  attrs = CFDictionaryCreateMutable (kCFAllocatorDefault, 3,
                                     &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue (attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
  CFDictionarySetValue (attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

  key = SecKeyCreateWithData (data, attrs, &cf_error);

  CFRelease (data);
  CFRelease (attrs);
  g_clear_pointer (&cf_error, CFRelease);

  return key;
}

#ifndef GIO_APPLE_PUBLIC_API_ONLY
static SecKeyRef
key_from_ed25519_curve (const guint8 *der,
                        gsize         len)
{
  SecKeyRef key;
  guint8 tag;
  const guint8 *seed;
  gsize seed_len, total;
  CFDataRef data;
  CFMutableDictionaryRef attrs;
  CFErrorRef cf_error = NULL;

  if (!asn1_read_tlv (der, len, &tag, &seed, &seed_len, &total) || tag != 0x04)
    return NULL;
  if (seed_len != 32)
    return NULL;

  data = CFDataCreate (kCFAllocatorDefault, seed, seed_len);
  if (!data)
    return NULL;

  attrs = CFDictionaryCreateMutable (kCFAllocatorDefault, 2,
                                     &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue (attrs, kSecAttrKeyType, kSecAttrKeyTypeEd25519);
  CFDictionarySetValue (attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

  key = SecKeyCreateWithData (data, attrs, &cf_error);

  CFRelease (data);
  CFRelease (attrs);
  g_clear_pointer (&cf_error, CFRelease);

  return key;
}
#endif

static Pkcs8Algo
extract_pkcs8_private_key (const guint8  *der,
                           gsize          len,
                           const guint8 **out_inner,
                           gsize         *out_inner_len)
{
  Pkcs8Algo algo = PKCS8_ALGO_UNKNOWN;
  guint8 tag;
  const guint8 *seq_body, *version_body, *algo_body, *oid_body, *key_body;
  gsize seq_len, version_len, algo_len, oid_len, key_len, total;
  gsize consumed;

  if (!asn1_read_tlv (der, len, &tag, &seq_body, &seq_len, &total) || tag != 0x30)
    return PKCS8_ALGO_UNKNOWN;

  if (!asn1_read_tlv (seq_body, seq_len, &tag, &version_body, &version_len, &total) || tag != 0x02)
    return PKCS8_ALGO_UNKNOWN;

  consumed = total;
  if (!asn1_read_tlv (seq_body + consumed, seq_len - consumed,
                      &tag, &algo_body, &algo_len, &total) || tag != 0x30)
    return PKCS8_ALGO_UNKNOWN;
  consumed += total;

  if (!asn1_read_tlv (algo_body, algo_len, &tag, &oid_body, &oid_len, &total) || tag != 0x06)
    return PKCS8_ALGO_UNKNOWN;

  if (oid_len == sizeof OID_RSA_ENCRYPTION && memcmp (oid_body, OID_RSA_ENCRYPTION, oid_len) == 0)
    algo = PKCS8_ALGO_RSA;
  else if (oid_len == sizeof OID_EC_PUBLIC_KEY && memcmp (oid_body, OID_EC_PUBLIC_KEY, oid_len) == 0)
    algo = PKCS8_ALGO_EC;
  else if (oid_len == sizeof OID_ED25519 && memcmp (oid_body, OID_ED25519, oid_len) == 0)
    algo = PKCS8_ALGO_ED25519;
  else
    return PKCS8_ALGO_UNKNOWN;

  if (!asn1_read_tlv (seq_body + consumed, seq_len - consumed,
                      &tag, &key_body, &key_len, &total) || tag != 0x04)
    return PKCS8_ALGO_UNKNOWN;

  *out_inner = key_body;
  *out_inner_len = key_len;
  return algo;
}

static gboolean
asn1_read_tlv (const guint8  *der,
               gsize          len,
               guint8        *out_tag,
               const guint8 **out_content,
               gsize         *out_content_len,
               gsize         *out_total_len)
{
  gsize cursor = 1;
  gsize length;
  gsize length_bytes;

  if (len < 2)
    return FALSE;

  *out_tag = der[0];

  if ((der[cursor] & 0x80) == 0)
    {
      length = der[cursor];
      cursor += 1;
    }
  else
    {
      length_bytes = der[cursor] & 0x7f;
      cursor += 1;
      if (length_bytes == 0 || length_bytes > 4 || cursor + length_bytes > len)
        return FALSE;

      length = 0;
      while (length_bytes-- > 0)
        {
          length = (length << 8) | der[cursor];
          cursor += 1;
        }
    }

  if (cursor + length > len)
    return FALSE;

  *out_content = der + cursor;
  *out_content_len = length;
  *out_total_len = cursor + length;
  return TRUE;
}

static void
g_tls_certificate_apple_get_property (GObject    *object,
                                      guint       prop_id,
                                      GValue     *value,
                                      GParamSpec *pspec)
{
  GTlsCertificateApple *self = G_TLS_CERTIFICATE_APPLE (object);

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      if (self->cert)
        {
          CFDataRef data = SecCertificateCopyData (self->cert);
          if (data)
            {
              GByteArray *arr = g_byte_array_sized_new ((guint) CFDataGetLength (data));
              g_byte_array_append (arr, CFDataGetBytePtr (data), (guint) CFDataGetLength (data));
              g_value_take_boxed (value, arr);
              CFRelease (data);
            }
        }
      break;

    case PROP_CERTIFICATE_PEM:
      {
        gchar *pem = cert_to_pem (self->cert);
        g_value_take_string (value, pem);
      }
      break;

    case PROP_PRIVATE_KEY:
    case PROP_PRIVATE_KEY_PEM:
      {
        GByteArray *pkcs8 = NULL;

        if (self->private_key)
          pkcs8 = export_private_key_pkcs8 (self->private_key);

        if (prop_id == PROP_PRIVATE_KEY)
          {
            g_value_take_boxed (value, pkcs8);
          }
        else if (pkcs8)
          {
            g_value_take_string (value,
                pem_encode_der ("PRIVATE KEY", pkcs8->data, pkcs8->len));
            g_byte_array_unref (pkcs8);
          }
      }
      break;

    case PROP_ISSUER:
      g_value_set_object (value, self->issuer);
      break;

    case PROP_NOT_VALID_BEFORE:
      if (self->cert)
        g_value_take_boxed (value, certificate_validity_date (self->cert, FALSE));
      break;

    case PROP_NOT_VALID_AFTER:
      if (self->cert)
        g_value_take_boxed (value, certificate_validity_date (self->cert, TRUE));
      break;

    case PROP_SUBJECT_NAME:
      if (self->cert)
        g_value_take_string (value, certificate_subject_name (self->cert));
      break;

    case PROP_ISSUER_NAME:
      if (self->cert)
        g_value_take_string (value, certificate_issuer_name (self->cert));
      break;

    case PROP_DNS_NAMES:
      if (self->cert)
        g_value_take_boxed (value, certificate_san_dns_names (self->cert));
      break;

    case PROP_IP_ADDRESSES:
      if (self->cert)
        g_value_take_boxed (value, certificate_san_ip_addresses (self->cert));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gchar *
cert_to_pem (SecCertificateRef cert)
{
  gchar *pem;
  CFDataRef data;

  if (!cert)
    return NULL;

  data = SecCertificateCopyData (cert);
  if (!data)
    return NULL;

  pem = pem_encode_der ("CERTIFICATE", CFDataGetBytePtr (data), (gsize) CFDataGetLength (data));
  CFRelease (data);
  return pem;
}

static GByteArray *
export_private_key_pkcs8 (SecKeyRef key)
{
  GByteArray *result = NULL;
  CFDictionaryRef attrs;
  CFStringRef key_type;
  gboolean is_rsa, is_ec, is_ed25519;
  CFNumberRef size_in_bits_ref;
  gint key_size_bits = 0;
  CFDataRef external;
  CFErrorRef cf_error = NULL;

  attrs = SecKeyCopyAttributes (key);
  if (!attrs)
    return NULL;

  key_type = CFDictionaryGetValue (attrs, kSecAttrKeyType);
  is_rsa     = key_type != NULL && CFEqual (key_type, kSecAttrKeyTypeRSA);
  is_ec      = key_type != NULL && CFEqual (key_type, kSecAttrKeyTypeECSECPrimeRandom);
#ifdef GIO_APPLE_PUBLIC_API_ONLY
  is_ed25519 = FALSE;
#else
  is_ed25519 = key_type != NULL && CFEqual (key_type, kSecAttrKeyTypeEd25519);
#endif
  size_in_bits_ref = CFDictionaryGetValue (attrs, kSecAttrKeySizeInBits);
  if (size_in_bits_ref != NULL)
    CFNumberGetValue (size_in_bits_ref, kCFNumberIntType, &key_size_bits);
  CFRelease (attrs);

  if (!is_rsa && !is_ec && !is_ed25519)
    return NULL;

  external = SecKeyCopyExternalRepresentation (key, &cf_error);
  if (!external)
    {
      g_clear_pointer (&cf_error, CFRelease);
      return NULL;
    }

  if (is_rsa)
    result = build_pkcs8_rsa (CFDataGetBytePtr (external), (gsize) CFDataGetLength (external));
  else if (is_ec)
    result = build_pkcs8_ec (CFDataGetBytePtr (external), (gsize) CFDataGetLength (external), key_size_bits);
  else
    result = build_pkcs8_ed25519 (CFDataGetBytePtr (external), (gsize) CFDataGetLength (external));

  CFRelease (external);
  return result;
}

static GByteArray *
build_pkcs8_rsa (const guint8 *pkcs1,
                 gsize         len)
{
  GByteArray *result = g_byte_array_new ();
  GByteArray *algo = g_byte_array_new ();
  GByteArray *body = g_byte_array_new ();

  der_append_oid (algo, OID_RSA_ENCRYPTION, sizeof OID_RSA_ENCRYPTION);
  der_append_null (algo);

  der_append_integer_uint (body, 0);
  der_append_sequence (body, algo->data, algo->len);
  der_append_octet_string (body, pkcs1, len);

  der_append_sequence (result, body->data, body->len);

  g_byte_array_unref (algo);
  g_byte_array_unref (body);
  return result;
}

static GByteArray *
build_pkcs8_ec (const guint8 *x963,
                gsize         x963_len,
                gint          key_size_bits)
{
  static const guint8 OID_SECP256R1[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
  static const guint8 OID_SECP384R1[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
  static const guint8 OID_SECP521R1[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
  GByteArray *result;
  const guint8 *curve_oid;
  gsize curve_oid_len;
  gsize coord_len;
  gsize public_point_len;
  const guint8 *public_point;
  const guint8 *private_scalar;
  GByteArray *sec1_body;
  GByteArray *sec1;
  GByteArray *params;
  GByteArray *public_bit_string;
  GByteArray *algo;
  GByteArray *body;

  switch (key_size_bits)
    {
      case 256: curve_oid = OID_SECP256R1; curve_oid_len = sizeof OID_SECP256R1; break;
      case 384: curve_oid = OID_SECP384R1; curve_oid_len = sizeof OID_SECP384R1; break;
      case 521: curve_oid = OID_SECP521R1; curve_oid_len = sizeof OID_SECP521R1; break;
      default:  return NULL;
    }

  coord_len = (key_size_bits + 7) / 8;
  public_point_len = 1 + 2 * coord_len;
  if (x963_len != public_point_len + coord_len || x963[0] != 0x04)
    return NULL;

  public_point = x963;
  private_scalar = x963 + public_point_len;

  sec1_body = g_byte_array_new ();
  der_append_integer_uint (sec1_body, 1);
  der_append_octet_string (sec1_body, private_scalar, coord_len);

  params = g_byte_array_new ();
  der_append_oid (params, curve_oid, curve_oid_len);
  der_append_tlv (sec1_body, 0xa0, params->data, params->len);

  public_bit_string = g_byte_array_new ();
  g_byte_array_append (public_bit_string, (const guint8 *) "\x00", 1);
  g_byte_array_append (public_bit_string, public_point, public_point_len);
  {
    GByteArray *wrapped = g_byte_array_new ();
    der_append_tlv (wrapped, 0x03, public_bit_string->data, public_bit_string->len);
    der_append_tlv (sec1_body, 0xa1, wrapped->data, wrapped->len);
    g_byte_array_unref (wrapped);
  }
  g_byte_array_unref (public_bit_string);

  sec1 = g_byte_array_new ();
  der_append_sequence (sec1, sec1_body->data, sec1_body->len);
  g_byte_array_unref (sec1_body);

  algo = g_byte_array_new ();
  der_append_oid (algo, OID_EC_PUBLIC_KEY, sizeof OID_EC_PUBLIC_KEY);
  der_append_oid (algo, curve_oid, curve_oid_len);

  body = g_byte_array_new ();
  der_append_integer_uint (body, 0);
  der_append_sequence (body, algo->data, algo->len);
  der_append_octet_string (body, sec1->data, sec1->len);
  g_byte_array_unref (algo);
  g_byte_array_unref (sec1);
  g_byte_array_unref (params);

  result = g_byte_array_new ();
  der_append_sequence (result, body->data, body->len);
  g_byte_array_unref (body);

  return result;
}

static GByteArray *
build_pkcs8_ed25519 (const guint8 *seed,
                     gsize         seed_len)
{
  GByteArray *result;
  GByteArray *algo;
  GByteArray *inner_octet;
  GByteArray *body;

  if (seed_len != 32)
    return NULL;

  algo = g_byte_array_new ();
  der_append_oid (algo, OID_ED25519, sizeof OID_ED25519);

  inner_octet = g_byte_array_new ();
  der_append_octet_string (inner_octet, seed, seed_len);

  body = g_byte_array_new ();
  der_append_integer_uint (body, 0);
  der_append_sequence (body, algo->data, algo->len);
  der_append_octet_string (body, inner_octet->data, inner_octet->len);
  g_byte_array_unref (algo);
  g_byte_array_unref (inner_octet);

  result = g_byte_array_new ();
  der_append_sequence (result, body->data, body->len);
  g_byte_array_unref (body);

  return result;
}

static void
der_append_tlv (GByteArray   *out,
                guint8        tag,
                const guint8 *value,
                gsize         length)
{
  g_byte_array_append (out, &tag, 1);
  der_append_length (out, length);
  if (length > 0)
    g_byte_array_append (out, value, (guint) length);
}

static void
der_append_length (GByteArray *out,
                   gsize       length)
{
  if (length < 0x80)
    {
      guint8 b = (guint8) length;
      g_byte_array_append (out, &b, 1);
      return;
    }

  {
    guint8 buf[8];
    gint i = 0;
    guint8 header;

    while (length > 0)
      {
        buf[i++] = (guint8) (length & 0xff);
        length >>= 8;
      }
    header = (guint8) (0x80 | i);
    g_byte_array_append (out, &header, 1);
    while (i > 0)
      g_byte_array_append (out, &buf[--i], 1);
  }
}

static void
der_append_sequence (GByteArray   *out,
                     const guint8 *content,
                     gsize         content_len)
{
  der_append_tlv (out, 0x30, content, content_len);
}

static void
der_append_integer_uint (GByteArray *out,
                         guint64     value)
{
  guint8 buf[9];
  gint n = 0;

  if (value == 0)
    {
      guint8 zero = 0;
      der_append_tlv (out, 0x02, &zero, 1);
      return;
    }

  while (value > 0)
    {
      buf[8 - n] = (guint8) (value & 0xff);
      value >>= 8;
      n++;
    }

  if (buf[9 - n] & 0x80)
    {
      buf[8 - n] = 0;
      n++;
    }

  der_append_tlv (out, 0x02, buf + 9 - n, (gsize) n);
}

static void
der_append_null (GByteArray *out)
{
  der_append_tlv (out, 0x05, NULL, 0);
}

static void
der_append_oid (GByteArray   *out,
                const guint8 *oid,
                gsize         length)
{
  der_append_tlv (out, 0x06, oid, length);
}

static void
der_append_octet_string (GByteArray   *out,
                         const guint8 *bytes,
                         gsize         length)
{
  der_append_tlv (out, 0x04, bytes, length);
}

static gchar *
pem_encode_der (const gchar  *label,
                const guint8 *der,
                gsize         der_len)
{
  gchar *base64;
  gsize base64_len;
  GString *pem;
  gsize i;

  base64 = g_base64_encode (der, der_len);
  base64_len = strlen (base64);

  pem = g_string_sized_new (base64_len + 128);
  g_string_append_printf (pem, "-----BEGIN %s-----\n", label);
  for (i = 0; i < base64_len; i += 64)
    {
      gsize chunk = MIN ((gsize) 64, base64_len - i);
      g_string_append_len (pem, base64 + i, chunk);
      g_string_append_c (pem, '\n');
    }
  g_string_append_printf (pem, "-----END %s-----\n", label);

  g_free (base64);
  return g_string_free (pem, FALSE);
}

static GDateTime *
certificate_validity_date (SecCertificateRef cert,
                           gboolean          want_not_after)
{
  GDateTime *result;
  CFDateRef cf_date = NULL;
  CFAbsoluteTime absolute;
  gint64 unix_seconds;

  if (__builtin_available (macOS 15.0, iOS 15.0, tvOS 15.0, watchOS 8.0, *))
    {
      cf_date = want_not_after
          ? SecCertificateCopyNotValidAfterDate (cert)
          : SecCertificateCopyNotValidBeforeDate (cert);
    }

  if (!cf_date)
    return NULL;

  absolute = CFDateGetAbsoluteTime (cf_date);
  unix_seconds = (gint64) (absolute + kCFAbsoluteTimeIntervalSince1970);
  result = g_date_time_new_from_unix_utc (unix_seconds);
  CFRelease (cf_date);
  return result;
}

static gchar *
certificate_subject_name (SecCertificateRef cert)
{
  gchar *result;
  CFDataRef der;

  der = SecCertificateCopyNormalizedSubjectSequence (cert);
  if (!der)
    return NULL;

  result = x500_name_to_string (CFDataGetBytePtr (der), CFDataGetLength (der));
  CFRelease (der);
  return result;
}

static gchar *
certificate_issuer_name (SecCertificateRef cert)
{
  gchar *result;
  CFDataRef der;

  der = SecCertificateCopyNormalizedIssuerSequence (cert);
  if (!der)
    return NULL;

  result = x500_name_to_string (CFDataGetBytePtr (der), CFDataGetLength (der));
  CFRelease (der);
  return result;
}

static gchar *
x500_name_to_string (const guint8 *der,
                     gsize         len)
{
  static const guint8 OID_CN[]    = { 0x55, 0x04, 0x03 };
  static const guint8 OID_C[]     = { 0x55, 0x04, 0x06 };
  static const guint8 OID_L[]     = { 0x55, 0x04, 0x07 };
  static const guint8 OID_ST[]    = { 0x55, 0x04, 0x08 };
  static const guint8 OID_O[]     = { 0x55, 0x04, 0x0a };
  static const guint8 OID_OU[]    = { 0x55, 0x04, 0x0b };
  static const guint8 OID_DC[]    = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 };
  static const guint8 OID_EMAIL[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 };
  static const struct
  {
    const guint8 *oid;
    gsize         len;
    const gchar  *short_name;
  } name_map[] = {
    { OID_CN,    sizeof OID_CN,    "CN"           },
    { OID_C,     sizeof OID_C,     "C"            },
    { OID_L,     sizeof OID_L,     "L"            },
    { OID_ST,    sizeof OID_ST,    "ST"           },
    { OID_O,     sizeof OID_O,     "O"            },
    { OID_OU,    sizeof OID_OU,    "OU"           },
    { OID_DC,    sizeof OID_DC,    "DC"           },
    { OID_EMAIL, sizeof OID_EMAIL, "emailAddress" },
  };

  GString *out;
  guint8 tag;
  const guint8 *seq_body;
  gsize seq_len, total, cursor;
  gboolean first = TRUE;

  if (!asn1_read_tlv (der, len, &tag, &seq_body, &seq_len, &total) || tag != 0x30)
    return NULL;

  out = g_string_new (NULL);
  cursor = 0;
  while (cursor < seq_len)
    {
      const guint8 *rdn_body;
      gsize rdn_len, inner_cursor = 0;

      if (!asn1_read_tlv (seq_body + cursor, seq_len - cursor,
                          &tag, &rdn_body, &rdn_len, &total) || tag != 0x31)
        break;
      cursor += total;

      while (inner_cursor < rdn_len)
        {
          const guint8 *atv_body, *oid_body, *val_body;
          gsize atv_len, atv_total, oid_len, oid_total, val_len;
          const gchar *short_name = NULL;
          guint i;

          if (!asn1_read_tlv (rdn_body + inner_cursor, rdn_len - inner_cursor,
                              &tag, &atv_body, &atv_len, &atv_total) || tag != 0x30)
            break;
          inner_cursor += atv_total;

          if (!asn1_read_tlv (atv_body, atv_len, &tag, &oid_body, &oid_len, &oid_total) || tag != 0x06)
            continue;

          for (i = 0; i < G_N_ELEMENTS (name_map); i++)
            {
              if (oid_len == name_map[i].len && memcmp (oid_body, name_map[i].oid, oid_len) == 0)
                {
                  short_name = name_map[i].short_name;
                  break;
                }
            }
          if (!short_name)
            continue;

          if (!asn1_read_tlv (atv_body + oid_total, atv_len - oid_total,
                              &tag, &val_body, &val_len, &total))
            continue;

          if (!first)
            g_string_append_c (out, ',');
          first = FALSE;
          g_string_append_printf (out, "%s=%.*s", short_name, (int) val_len, (const gchar *) val_body);
        }
    }

  if (out->len == 0)
    {
      g_string_free (out, TRUE);
      return NULL;
    }
  return g_string_free (out, FALSE);
}

static GPtrArray *
certificate_san_dns_names (SecCertificateRef cert)
{
  GPtrArray *dns_names;
  guint8 *san_value;
  gsize san_value_len;

  if (!find_subject_alt_name_der (cert, &san_value, &san_value_len))
    return NULL;

  dns_names = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  collect_general_names (san_value, san_value_len, dns_names, NULL);
  g_free (san_value);

  if (dns_names->len == 0)
    {
      g_ptr_array_free (dns_names, TRUE);
      return NULL;
    }
  return dns_names;
}

static GPtrArray *
certificate_san_ip_addresses (SecCertificateRef cert)
{
  GPtrArray *ip_addresses;
  guint8 *san_value;
  gsize san_value_len;

  if (!find_subject_alt_name_der (cert, &san_value, &san_value_len))
    return NULL;

  ip_addresses = g_ptr_array_new_with_free_func (g_object_unref);
  collect_general_names (san_value, san_value_len, NULL, ip_addresses);
  g_free (san_value);

  if (ip_addresses->len == 0)
    {
      g_ptr_array_free (ip_addresses, TRUE);
      return NULL;
    }
  return ip_addresses;
}

static gboolean
find_subject_alt_name_der (SecCertificateRef cert,
                           guint8          **out_value,
                           gsize            *out_value_len)
{
  static const guint8 OID_SUBJECT_ALT_NAME[] = { 0x55, 0x1d, 0x11 };
  gboolean found = FALSE;
  CFDataRef data;
  const guint8 *bytes;
  gsize total_len, consumed;
  guint8 tag;
  const guint8 *cert_body, *tbs_body;
  gsize cert_len, tbs_len, extensions_len;
  const guint8 *extensions_body = NULL;
  const guint8 *cursor_p;
  gsize cursor_rem, advance;

  data = SecCertificateCopyData (cert);
  if (!data)
    return FALSE;
  bytes = CFDataGetBytePtr (data);
  total_len = CFDataGetLength (data);

  if (!asn1_read_tlv (bytes, total_len, &tag, &cert_body, &cert_len, &advance) || tag != 0x30)
    goto done;
  if (!asn1_read_tlv (cert_body, cert_len, &tag, &tbs_body, &tbs_len, &advance) || tag != 0x30)
    goto done;

  cursor_p = tbs_body;
  cursor_rem = tbs_len;
  while (cursor_rem > 0)
    {
      const guint8 *body;
      gsize body_len;

      if (!asn1_read_tlv (cursor_p, cursor_rem, &tag, &body, &body_len, &advance))
        break;
      if (tag == 0xa3)
        {
          if (asn1_read_tlv (body, body_len, &tag, &extensions_body, &extensions_len, &advance) && tag == 0x30)
            break;
          extensions_body = NULL;
        }
      cursor_p += advance;
      cursor_rem -= advance;
    }

  if (!extensions_body)
    goto done;

  consumed = 0;
  while (consumed < extensions_len)
    {
      const guint8 *ext_body, *oid_body, *ext_val;
      gsize ext_len, oid_len, ext_val_len;

      if (!asn1_read_tlv (extensions_body + consumed, extensions_len - consumed,
                          &tag, &ext_body, &ext_len, &advance) || tag != 0x30)
        break;
      consumed += advance;

      if (!asn1_read_tlv (ext_body, ext_len, &tag, &oid_body, &oid_len, &advance) || tag != 0x06)
        continue;

      if (oid_len == sizeof OID_SUBJECT_ALT_NAME &&
          memcmp (oid_body, OID_SUBJECT_ALT_NAME, oid_len) == 0)
        {
          gsize after_oid = (oid_body - ext_body) + oid_len;
          const guint8 *p = ext_body + after_oid;
          gsize rem = ext_len - after_oid;
          const guint8 *maybe_bool_body;
          gsize maybe_bool_len;

          if (asn1_read_tlv (p, rem, &tag, &maybe_bool_body, &maybe_bool_len, &advance) &&
              tag == 0x01)
            {
              p += advance;
              rem -= advance;
            }

          if (asn1_read_tlv (p, rem, &tag, &ext_val, &ext_val_len, &advance) && tag == 0x04)
            {
              *out_value = g_memdup2 (ext_val, ext_val_len);
              *out_value_len = ext_val_len;
              found = TRUE;
            }
          break;
        }
    }

done:
  CFRelease (data);
  return found;
}

static void
collect_general_names (const guint8 *der,
                       gsize         len,
                       GPtrArray    *out_dns,
                       GPtrArray    *out_ip)
{
  guint8 tag;
  const guint8 *seq_body, *name_body;
  gsize seq_len, name_len, advance, cursor;

  if (!asn1_read_tlv (der, len, &tag, &seq_body, &seq_len, &advance) || tag != 0x30)
    return;

  cursor = 0;
  while (cursor < seq_len)
    {
      if (!asn1_read_tlv (seq_body + cursor, seq_len - cursor,
                          &tag, &name_body, &name_len, &advance))
        break;
      cursor += advance;

      if (tag == 0x82 && out_dns)
        g_ptr_array_add (out_dns, g_bytes_new (name_body, name_len));
      else if (tag == 0x87 && out_ip)
        {
          GInetAddress *addr = NULL;
          if (name_len == 4)
            addr = g_inet_address_new_from_bytes (name_body, G_SOCKET_FAMILY_IPV4);
          else if (name_len == 16)
            addr = g_inet_address_new_from_bytes (name_body, G_SOCKET_FAMILY_IPV6);
          if (addr)
            g_ptr_array_add (out_ip, addr);
        }
    }
}

static GTlsCertificateFlags
g_tls_certificate_apple_verify (GTlsCertificate     *cert,
                                GSocketConnectable  *identity,
                                GTlsCertificate     *trusted_ca)
{
  GTlsCertificateFlags result;
  CFMutableArrayRef chain;
  GTlsCertificate *cursor;
  SecPolicyRef policy;
  SecTrustRef trust = NULL;
  OSStatus status;
  CFErrorRef cf_error = NULL;

  if (!G_IS_TLS_CERTIFICATE_APPLE (cert))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  chain = CFArrayCreateMutable (kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  for (cursor = cert; cursor; cursor = g_tls_certificate_get_issuer (cursor))
    {
      SecCertificateRef ref;

      if (!G_IS_TLS_CERTIFICATE_APPLE (cursor))
        {
          CFRelease (chain);
          return G_TLS_CERTIFICATE_GENERIC_ERROR;
        }

      ref = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (cursor));
      if (!ref)
        {
          CFRelease (chain);
          return G_TLS_CERTIFICATE_GENERIC_ERROR;
        }

      CFArrayAppendValue (chain, ref);
    }

  policy = SecPolicyCreateBasicX509 ();
  if (!policy)
    {
      CFRelease (chain);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  status = SecTrustCreateWithCertificates (chain, policy, &trust);
  CFRelease (chain);
  CFRelease (policy);

  if (status != errSecSuccess || !trust)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  if (G_IS_TLS_CERTIFICATE_APPLE (trusted_ca))
    {
      SecCertificateRef anchor = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (trusted_ca));
      if (anchor)
        {
          CFArrayRef anchors = CFArrayCreate (kCFAllocatorDefault,
              (const void *[]) { anchor }, 1, &kCFTypeArrayCallBacks);
          SecTrustSetAnchorCertificates (trust, anchors);
          SecTrustSetAnchorCertificatesOnly (trust, true);
          CFRelease (anchors);
        }
    }

  if (SecTrustEvaluateWithError (trust, &cf_error))
    {
      CFRelease (trust);
      result = 0;
    }
  else
    {
      result = G_TLS_CERTIFICATE_UNKNOWN_CA;
      if (cf_error)
        {
          switch (CFErrorGetCode (cf_error))
            {
            case errSecCertificateExpired:
              result = certificate_is_not_yet_valid (cert)
                  ? G_TLS_CERTIFICATE_NOT_ACTIVATED
                  : G_TLS_CERTIFICATE_EXPIRED;
              break;
            case errSecCertificateNotValidYet:
              result = G_TLS_CERTIFICATE_NOT_ACTIVATED;
              break;
            case errSecCertificateRevoked:
              result = G_TLS_CERTIFICATE_REVOKED;
              break;
            }
          CFRelease (cf_error);
        }
      CFRelease (trust);
    }

  if (identity &&
      !g_tls_certificate_apple_matches_identity (G_TLS_CERTIFICATE_APPLE (cert), identity))
    result |= G_TLS_CERTIFICATE_BAD_IDENTITY;

  return result;
}

static gboolean
certificate_is_not_yet_valid (GTlsCertificate *cert)
{
  gboolean in_future;
  GDateTime *not_before = NULL;
  GDateTime *now;

  g_object_get (cert, "not-valid-before", &not_before, NULL);
  if (!not_before)
    return FALSE;

  now = g_date_time_new_now_utc ();
  in_future = g_date_time_compare (not_before, now) > 0;

  g_date_time_unref (now);
  g_date_time_unref (not_before);
  return in_future;
}

static void
g_tls_certificate_apple_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_certificate_apple_initable_init;
}

static gboolean
g_tls_certificate_apple_initable_init (GInitable     *initable,
                                       GCancellable  *cancellable,
                                       GError       **error)
{
  GTlsCertificateApple *self = G_TLS_CERTIFICATE_APPLE (initable);

  if (self->construct_error)
    {
      g_propagate_error (error, self->construct_error);
      self->construct_error = NULL;
      return FALSE;
    }

  if (self->pkcs12_data && !self->have_cert)
    {
      if (!import_pkcs12 (self, error))
        return FALSE;
    }

  g_clear_pointer (&self->pkcs12_data, g_byte_array_unref);
  g_free (self->password);
  self->password = NULL;

  if (!self->have_cert)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("No certificate data provided"));
      return FALSE;
    }

  return TRUE;
}

static gboolean
import_pkcs12 (GTlsCertificateApple  *self,
               GError               **error)
{
  CFDataRef data;
  CFDictionaryRef options;
  CFArrayRef items = NULL;
  OSStatus status;
  CFDictionaryRef first;
  SecIdentityRef identity;

  if (!self->pkcs12_data)
    return TRUE;

  data = CFDataCreate (kCFAllocatorDefault, self->pkcs12_data->data, self->pkcs12_data->len);
  if (!data)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Unable to allocate CFData for PKCS#12 import"));
      return FALSE;
    }

  {
    CFStringRef pw = self->password != NULL
        ? CFStringCreateWithCString (kCFAllocatorDefault, self->password, kCFStringEncodingUTF8)
        : CFSTR ("");
    options = CFDictionaryCreate (kCFAllocatorDefault,
        (const void *[]) { kSecImportExportPassphrase, kSecImportToMemoryOnly },
        (const void *[]) { pw, kCFBooleanTrue },
        2,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (self->password != NULL)
      CFRelease (pw);
  }

  status = SecPKCS12Import (data, options, &items);
  CFRelease (data);
  CFRelease (options);

  if (status != errSecSuccess || !items || CFArrayGetCount (items) == 0)
    {
      g_clear_pointer (&items, CFRelease);

      if (self->password == NULL && import_pkcs12_plain (self))
        return TRUE;

      if (status == errSecAuthFailed)
        g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE_PASSWORD,
                             _("Wrong password for PKCS#12 bundle"));
      else
        g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                     _("Could not parse PKCS#12 bundle (OSStatus %d)"), (int) status);
      return FALSE;
    }

  first = CFArrayGetValueAtIndex (items, 0);
  identity = (SecIdentityRef) CFDictionaryGetValue (first, kSecImportItemIdentity);
  if (identity)
    {
      SecCertificateRef cert = NULL;
      SecKeyRef key = NULL;

      SecIdentityCopyCertificate (identity, &cert);
      SecIdentityCopyPrivateKey (identity, &key);

      if (cert)
        {
          g_clear_pointer (&self->cert, CFRelease);
          self->cert = cert;
          self->have_cert = TRUE;
        }
      if (key)
        {
          g_clear_pointer (&self->private_key, CFRelease);
          self->private_key = key;
          self->have_key = TRUE;
        }

      g_clear_pointer (&self->identity, CFRelease);
      self->identity = (SecIdentityRef) CFRetain (identity);
    }

  chain_extra_certs_from_pkcs12 (self, items);

  CFRelease (items);
  return TRUE;
}

static void
chain_extra_certs_from_pkcs12 (GTlsCertificateApple *self,
                               CFArrayRef            items)
{
  CFDictionaryRef first;
  CFArrayRef extra_chain;
  GTlsCertificateApple *tail;
  CFIndex i;

  if (CFArrayGetCount (items) == 0)
    return;

  first = CFArrayGetValueAtIndex (items, 0);
  extra_chain = CFDictionaryGetValue (first, kSecImportItemCertChain);
  if (!extra_chain || CFArrayGetCount (extra_chain) < 2)
    return;

  tail = self;
  for (i = 1; i < CFArrayGetCount (extra_chain); i++)
    {
      SecCertificateRef ref = (SecCertificateRef) CFArrayGetValueAtIndex (extra_chain, i);
      GTlsCertificate *wrapper = g_tls_certificate_apple_new_from_sec (ref, NULL, NULL);

      if (!wrapper)
        continue;

      g_object_set (tail, "issuer", wrapper, NULL);
      tail = G_TLS_CERTIFICATE_APPLE (wrapper);
      g_object_unref (wrapper);
    }
}

static gboolean
import_pkcs12_plain (GTlsCertificateApple *self)
{
  static const guint8 OID_CERT_BAG[]         = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03 };
  static const guint8 OID_KEY_BAG[]          = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01 };
  static const guint8 OID_X509_CERTIFICATE[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01 };

  gboolean ok = FALSE;
  GArray *cert_ders = g_array_new (FALSE, FALSE, sizeof (DerSlice));
  DerSlice key_pkcs8 = { NULL, 0 };
  guint8 tag;
  const guint8 *pfx_body, *cursor, *auth_safe, *skip;
  gsize pfx_body_len, remaining, auth_safe_len, skip_len, total;
  SecCertificateRef first_cert = NULL;
  SecKeyRef key = NULL;

  if (!asn1_read_tlv (self->pkcs12_data->data, self->pkcs12_data->len,
                      &tag, &pfx_body, &pfx_body_len, &total) || tag != 0x30)
    goto out;

  if (!asn1_read_tlv (pfx_body, pfx_body_len, &tag, &skip, &skip_len, &total) || tag != 0x02)
    goto out;
  cursor = pfx_body + total;
  remaining = pfx_body_len - total;

  if (!parse_pkcs7_data_body (cursor, remaining, &total, &auth_safe, &auth_safe_len))
    goto out;

  if (!asn1_read_tlv (auth_safe, auth_safe_len, &tag, &auth_safe, &auth_safe_len, &total) || tag != 0x30)
    goto out;

  cursor = auth_safe;
  remaining = auth_safe_len;

  while (remaining > 0)
    {
      const guint8 *safe_contents_body, *bags_seq, *bag_cursor;
      gsize safe_contents_body_len, bags_seq_len, bag_remaining;

      if (!parse_pkcs7_data_body (cursor, remaining, &total,
                                  &safe_contents_body, &safe_contents_body_len))
        goto out;
      cursor += total;
      remaining -= total;

      if (!asn1_read_tlv (safe_contents_body, safe_contents_body_len,
                          &tag, &bags_seq, &bags_seq_len, &total) || tag != 0x30)
        goto out;

      bag_cursor = bags_seq;
      bag_remaining = bags_seq_len;

      while (bag_remaining > 0)
        {
          const guint8 *bag_body, *oid_body, *value_body;
          gsize bag_body_len, oid_len, value_len, bag_total, t;

          if (!asn1_read_tlv (bag_cursor, bag_remaining,
                              &tag, &bag_body, &bag_body_len, &bag_total) || tag != 0x30)
            goto out;
          bag_cursor += bag_total;
          bag_remaining -= bag_total;

          if (!asn1_read_tlv (bag_body, bag_body_len, &tag, &oid_body, &oid_len, &t) || tag != 0x06)
            goto out;

          if (!asn1_read_tlv (bag_body + t, bag_body_len - t,
                              &tag, &value_body, &value_len, &t) || tag != 0xa0)
            goto out;

          if (oid_len == sizeof OID_CERT_BAG && memcmp (oid_body, OID_CERT_BAG, oid_len) == 0)
            {
              const guint8 *cert_bag, *cert_octet;
              gsize cert_bag_len, cert_octet_len;
              DerSlice slice;

              if (!asn1_read_tlv (value_body, value_len, &tag, &cert_bag, &cert_bag_len, &t) || tag != 0x30)
                continue;
              if (!asn1_read_tlv (cert_bag, cert_bag_len, &tag, &oid_body, &oid_len, &t) || tag != 0x06)
                continue;
              if (oid_len != sizeof OID_X509_CERTIFICATE ||
                  memcmp (oid_body, OID_X509_CERTIFICATE, oid_len) != 0)
                continue;
              cert_bag += t;
              cert_bag_len -= t;
              if (!asn1_read_tlv (cert_bag, cert_bag_len, &tag, &cert_octet, &cert_octet_len, &t) || tag != 0xa0)
                continue;
              if (!asn1_read_tlv (cert_octet, cert_octet_len, &tag, &cert_octet, &cert_octet_len, &t) || tag != 0x04)
                continue;

              slice.data = cert_octet;
              slice.len = cert_octet_len;
              g_array_append_val (cert_ders, slice);
            }
          else if (oid_len == sizeof OID_KEY_BAG && memcmp (oid_body, OID_KEY_BAG, oid_len) == 0)
            {
              if (key_pkcs8.data == NULL)
                {
                  key_pkcs8.data = value_body;
                  key_pkcs8.len = value_len;
                }
            }
        }
    }

  if (cert_ders->len == 0 || key_pkcs8.data == NULL)
    goto out;

  {
    DerSlice *leaf = &g_array_index (cert_ders, DerSlice, 0);
    CFDataRef data = CFDataCreate (kCFAllocatorDefault, leaf->data, leaf->len);
    if (!data)
      goto out;
    first_cert = SecCertificateCreateWithData (kCFAllocatorDefault, data);
    CFRelease (data);
    if (!first_cert)
      goto out;
  }

  key = key_from_der (key_pkcs8.data, key_pkcs8.len, NULL);
  if (!key)
    goto out;

  g_clear_pointer (&self->cert, CFRelease);
  self->cert = g_steal_pointer (&first_cert);
  self->have_cert = TRUE;

  g_clear_pointer (&self->private_key, CFRelease);
  self->private_key = g_steal_pointer (&key);
  self->have_key = TRUE;

  {
    GTlsCertificateApple *tail = self;
    guint i;

    for (i = 1; i < cert_ders->len; i++)
      {
        DerSlice *slice = &g_array_index (cert_ders, DerSlice, i);
        CFDataRef data;
        SecCertificateRef ref;
        GTlsCertificate *wrapper;

        data = CFDataCreate (kCFAllocatorDefault, slice->data, slice->len);
        if (!data)
          continue;
        ref = SecCertificateCreateWithData (kCFAllocatorDefault, data);
        CFRelease (data);
        if (!ref)
          continue;

        wrapper = g_tls_certificate_apple_new_from_sec (ref, NULL, NULL);
        CFRelease (ref);
        if (!wrapper)
          continue;

        g_object_set (tail, "issuer", wrapper, NULL);
        tail = G_TLS_CERTIFICATE_APPLE (wrapper);
        g_object_unref (wrapper);
      }
  }

  ok = TRUE;

out:
  g_clear_pointer (&first_cert, CFRelease);
  g_clear_pointer (&key, CFRelease);
  g_array_unref (cert_ders);
  return ok;
}

static gboolean
parse_pkcs7_data_body (const guint8  *der,
                       gsize          len,
                       gsize         *out_total,
                       const guint8 **out_body,
                       gsize         *out_body_len)
{
  static const guint8 OID_PKCS7_DATA[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };

  guint8 tag;
  const guint8 *body, *oid_body, *ctx_body, *octet_body;
  gsize body_len, oid_len, ctx_len, octet_len, total;

  if (!asn1_read_tlv (der, len, &tag, &body, &body_len, out_total) || tag != 0x30)
    return FALSE;

  if (!asn1_read_tlv (body, body_len, &tag, &oid_body, &oid_len, &total) || tag != 0x06)
    return FALSE;
  if (oid_len != sizeof OID_PKCS7_DATA || memcmp (oid_body, OID_PKCS7_DATA, oid_len) != 0)
    return FALSE;

  if (!asn1_read_tlv (body + total, body_len - total,
                      &tag, &ctx_body, &ctx_len, &total) || tag != 0xa0)
    return FALSE;

  if (!asn1_read_tlv (ctx_body, ctx_len, &tag, &octet_body, &octet_len, &total) || tag != 0x04)
    return FALSE;

  *out_body = octet_body;
  *out_body_len = octet_len;
  return TRUE;
}

GTlsCertificate *
g_tls_certificate_apple_new_from_sec (SecCertificateRef  cert,
                                      SecKeyRef          private_key,
                                      GTlsCertificate   *issuer)
{
  GTlsCertificateApple *self;

  if (!cert)
    return NULL;

  self = g_object_new (G_TYPE_TLS_CERTIFICATE_APPLE, NULL);
  self->cert = (SecCertificateRef) CFRetain (cert);
  self->have_cert = TRUE;
  if (private_key)
    {
      self->private_key = (SecKeyRef) CFRetain (private_key);
      self->have_key = TRUE;
    }
  if (issuer)
    self->issuer = G_TLS_CERTIFICATE_APPLE (g_object_ref (issuer));

  return G_TLS_CERTIFICATE (self);
}

SecCertificateRef
g_tls_certificate_apple_get_cert (GTlsCertificateApple *self)
{
  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_APPLE (self), NULL);
  return self->cert;
}

SecKeyRef
g_tls_certificate_apple_get_private_key (GTlsCertificateApple *self)
{
  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_APPLE (self), NULL);
  return self->private_key;
}

SecIdentityRef
g_tls_certificate_apple_copy_identity (GTlsCertificateApple *self)
{
  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_APPLE (self), NULL);

  if (self->identity)
    return (SecIdentityRef) CFRetain (self->identity);

  if (self->cert && self->private_key)
    {
      self->identity = synthesize_identity (self->cert, self->private_key);
      if (self->identity)
        return (SecIdentityRef) CFRetain (self->identity);
    }

  return NULL;
}

static SecIdentityRef
synthesize_identity (SecCertificateRef cert,
                     SecKeyRef         key)
{
  static const gchar transit_password[] = "pkcs12-synthesis";
  SecIdentityRef identity = NULL;
  GByteArray *blob;
  CFDataRef data;
  CFStringRef password;
  const void *keys[2];
  const void *values[2];
  CFDictionaryRef options;
  OSStatus status;
  CFArrayRef items = NULL;

  blob = build_pkcs12 (cert, key, transit_password);
  if (!blob)
    return NULL;

  data = CFDataCreate (kCFAllocatorDefault, blob->data, blob->len);
  g_byte_array_unref (blob);
  if (!data)
    return NULL;

  password = CFStringCreateWithCString (kCFAllocatorDefault, transit_password, kCFStringEncodingUTF8);
  keys[0] = kSecImportExportPassphrase;
  values[0] = password;
  keys[1] = kSecImportToMemoryOnly;
  values[1] = kCFBooleanTrue;
  options = CFDictionaryCreate (kCFAllocatorDefault, keys, values, 2,
                                &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);

  status = SecPKCS12Import (data, options, &items);
  CFRelease (data);
  CFRelease (options);
  CFRelease (password);

  if (status == errSecSuccess && items && CFArrayGetCount (items) > 0)
    {
      CFDictionaryRef first = CFArrayGetValueAtIndex (items, 0);
      SecIdentityRef ref = (SecIdentityRef) CFDictionaryGetValue (first, kSecImportItemIdentity);
      if (ref)
        identity = (SecIdentityRef) CFRetain (ref);
    }

  if (items)
    CFRelease (items);

  return identity;
}

static GByteArray *
build_pkcs12 (SecCertificateRef cert,
              SecKeyRef         key,
              const gchar      *password)
{
  static const guint8 oid_id_data[]           = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };
  static const guint8 oid_cert_bag[]          = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03 };
  static const guint8 oid_x509_cert[]         = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01 };
  static const guint8 oid_shrouded_key_bag[]  = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02 };

  GByteArray *pfx;
  CFDataRef cert_data;
  GByteArray *pkcs8;
  GByteArray *cert_bag_value_inner;
  GByteArray *cert_bag_value;
  GByteArray *cert_safe_bag;
  GByteArray *key_safe_bag;
  GByteArray *safe_contents_body;
  GByteArray *safe_contents;
  GByteArray *inner_ci_content;
  GByteArray *inner_ci_body;
  GByteArray *inner_ci;
  GByteArray *auth_safe_body;
  GByteArray *auth_safe_content;
  GByteArray *auth_safe_ci_body;
  GByteArray *auth_safe_ci;
  GByteArray *pfx_body;

  cert_data = SecCertificateCopyData (cert);
  if (!cert_data)
    return NULL;

  pkcs8 = export_private_key_pkcs8 (key);
  if (!pkcs8)
    {
      CFRelease (cert_data);
      return NULL;
    }

  cert_bag_value_inner = g_byte_array_new ();
  der_append_oid (cert_bag_value_inner, oid_x509_cert, sizeof oid_x509_cert);
  {
    GByteArray *octet = g_byte_array_new ();
    der_append_octet_string (octet, CFDataGetBytePtr (cert_data), (gsize) CFDataGetLength (cert_data));
    der_append_tlv (cert_bag_value_inner, 0xa0, octet->data, octet->len);
    g_byte_array_unref (octet);
  }
  CFRelease (cert_data);

  cert_bag_value = g_byte_array_new ();
  der_append_sequence (cert_bag_value, cert_bag_value_inner->data, cert_bag_value_inner->len);
  g_byte_array_unref (cert_bag_value_inner);

  {
    static const guint8 local_key_id[] = { 0x01 };
    GByteArray *encrypted_key;

    cert_safe_bag = build_safe_bag (oid_cert_bag, sizeof oid_cert_bag,
                                    cert_bag_value->data, cert_bag_value->len,
                                    local_key_id, sizeof local_key_id);
    g_byte_array_unref (cert_bag_value);

    encrypted_key = encrypt_pkcs8_pbes2 (pkcs8->data, pkcs8->len, password);
    g_byte_array_unref (pkcs8);
    if (!encrypted_key)
      {
        g_byte_array_unref (cert_safe_bag);
        return NULL;
      }

    key_safe_bag = build_safe_bag (oid_shrouded_key_bag, sizeof oid_shrouded_key_bag,
                                   encrypted_key->data, encrypted_key->len,
                                   local_key_id, sizeof local_key_id);
    g_byte_array_unref (encrypted_key);
  }

  safe_contents_body = g_byte_array_new ();
  g_byte_array_append (safe_contents_body, cert_safe_bag->data, cert_safe_bag->len);
  g_byte_array_append (safe_contents_body, key_safe_bag->data, key_safe_bag->len);
  g_byte_array_unref (cert_safe_bag);
  g_byte_array_unref (key_safe_bag);

  safe_contents = g_byte_array_new ();
  der_append_sequence (safe_contents, safe_contents_body->data, safe_contents_body->len);
  g_byte_array_unref (safe_contents_body);

  inner_ci_content = g_byte_array_new ();
  der_append_octet_string (inner_ci_content, safe_contents->data, safe_contents->len);
  g_byte_array_unref (safe_contents);

  inner_ci_body = g_byte_array_new ();
  der_append_oid (inner_ci_body, oid_id_data, sizeof oid_id_data);
  der_append_tlv (inner_ci_body, 0xa0, inner_ci_content->data, inner_ci_content->len);
  g_byte_array_unref (inner_ci_content);

  inner_ci = g_byte_array_new ();
  der_append_sequence (inner_ci, inner_ci_body->data, inner_ci_body->len);
  g_byte_array_unref (inner_ci_body);

  auth_safe_body = g_byte_array_new ();
  der_append_sequence (auth_safe_body, inner_ci->data, inner_ci->len);
  g_byte_array_unref (inner_ci);

  auth_safe_content = g_byte_array_new ();
  der_append_octet_string (auth_safe_content, auth_safe_body->data, auth_safe_body->len);

  auth_safe_ci_body = g_byte_array_new ();
  der_append_oid (auth_safe_ci_body, oid_id_data, sizeof oid_id_data);
  der_append_tlv (auth_safe_ci_body, 0xa0, auth_safe_content->data, auth_safe_content->len);
  g_byte_array_unref (auth_safe_content);

  auth_safe_ci = g_byte_array_new ();
  der_append_sequence (auth_safe_ci, auth_safe_ci_body->data, auth_safe_ci_body->len);
  g_byte_array_unref (auth_safe_ci_body);

  pfx_body = g_byte_array_new ();
  der_append_integer_uint (pfx_body, 3);
  g_byte_array_append (pfx_body, auth_safe_ci->data, auth_safe_ci->len);
  g_byte_array_unref (auth_safe_ci);

  {
    GByteArray *mac_data = build_pkcs12_mac_data (auth_safe_body->data, auth_safe_body->len, password);
    g_byte_array_append (pfx_body, mac_data->data, mac_data->len);
    g_byte_array_unref (mac_data);
  }
  g_byte_array_unref (auth_safe_body);

  pfx = g_byte_array_new ();
  der_append_sequence (pfx, pfx_body->data, pfx_body->len);
  g_byte_array_unref (pfx_body);

  return pfx;
}

static GByteArray *
build_safe_bag (const guint8 *bag_id,
                gsize         bag_id_len,
                const guint8 *bag_value,
                gsize         bag_value_len,
                const guint8 *local_key_id,
                gsize         local_key_id_len)
{
  static const guint8 oid_local_key_id[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15 };
  GByteArray *body = g_byte_array_new ();
  GByteArray *bag = g_byte_array_new ();

  der_append_oid (body, bag_id, bag_id_len);
  der_append_tlv (body, 0xa0, bag_value, bag_value_len);

  if (local_key_id != NULL && local_key_id_len > 0)
    {
      GByteArray *value_octet = g_byte_array_new ();
      GByteArray *value_set = g_byte_array_new ();
      GByteArray *attr_body = g_byte_array_new ();
      GByteArray *attr_seq = g_byte_array_new ();
      GByteArray *attrs_set = g_byte_array_new ();

      der_append_octet_string (value_octet, local_key_id, local_key_id_len);
      der_append_tlv (value_set, 0x31, value_octet->data, value_octet->len);
      g_byte_array_unref (value_octet);

      der_append_oid (attr_body, oid_local_key_id, sizeof oid_local_key_id);
      g_byte_array_append (attr_body, value_set->data, value_set->len);
      g_byte_array_unref (value_set);

      der_append_sequence (attr_seq, attr_body->data, attr_body->len);
      g_byte_array_unref (attr_body);

      der_append_tlv (attrs_set, 0x31, attr_seq->data, attr_seq->len);
      g_byte_array_unref (attr_seq);

      g_byte_array_append (body, attrs_set->data, attrs_set->len);
      g_byte_array_unref (attrs_set);
    }

  der_append_sequence (bag, body->data, body->len);
  g_byte_array_unref (body);
  return bag;
}

static GByteArray *
build_pkcs12_mac_data (const guint8 *auth_safe,
                       gsize         auth_safe_len,
                       const gchar  *password)
{
  static const guint8 oid_sha256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
  const guint mac_iterations = 2048;
  guint8 salt[8];
  guint8 mac_key[CC_SHA256_DIGEST_LENGTH];
  guint8 mac[CC_SHA256_DIGEST_LENGTH];
  GByteArray *digest_algorithm;
  GByteArray *digest_info_body;
  GByteArray *digest_info;
  GByteArray *mac_data_body;
  GByteArray *mac_data;
  guint i;

  for (i = 0; i < sizeof salt; i++)
    salt[i] = (guint8) g_random_int_range (0, 256);

  pkcs12_kdf (password, salt, sizeof salt, mac_iterations, 3,
              mac_key, sizeof mac_key);

  CCHmac (kCCHmacAlgSHA256, mac_key, sizeof mac_key,
          auth_safe, auth_safe_len, mac);

  digest_algorithm = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    der_append_oid (inner, oid_sha256, sizeof oid_sha256);
    der_append_null (inner);
    der_append_sequence (digest_algorithm, inner->data, inner->len);
    g_byte_array_unref (inner);
  }

  digest_info_body = g_byte_array_new ();
  g_byte_array_append (digest_info_body, digest_algorithm->data, digest_algorithm->len);
  der_append_octet_string (digest_info_body, mac, sizeof mac);
  g_byte_array_unref (digest_algorithm);

  digest_info = g_byte_array_new ();
  der_append_sequence (digest_info, digest_info_body->data, digest_info_body->len);
  g_byte_array_unref (digest_info_body);

  mac_data_body = g_byte_array_new ();
  g_byte_array_append (mac_data_body, digest_info->data, digest_info->len);
  der_append_octet_string (mac_data_body, salt, sizeof salt);
  der_append_integer_uint (mac_data_body, mac_iterations);
  g_byte_array_unref (digest_info);

  mac_data = g_byte_array_new ();
  der_append_sequence (mac_data, mac_data_body->data, mac_data_body->len);
  g_byte_array_unref (mac_data_body);

  return mac_data;
}

static GByteArray *
encrypt_pkcs8_pbes2 (const guint8 *pkcs8,
                     gsize         pkcs8_len,
                     const gchar  *password)
{
  static const guint8 oid_pbes2[]       = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };
  static const guint8 oid_pbkdf2[]      = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
  static const guint8 oid_aes256_cbc[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a };
  static const guint8 oid_hmac_sha256[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09 };
  const guint iterations = 2048;
  const gsize key_len = 32;
  const gsize iv_len = 16;
  guint8 salt[8];
  guint8 iv[16];
  guint8 derived[32];
  CCCryptorStatus cs;
  gsize ciphertext_cap;
  guint8 *ciphertext;
  size_t produced = 0;
  GByteArray *kdf_params;
  GByteArray *kdf_algid;
  GByteArray *enc_algid;
  GByteArray *pbes2_params;
  GByteArray *pbes2_algid;
  GByteArray *encrypted;
  guint i;

  for (i = 0; i < sizeof salt; i++)
    salt[i] = (guint8) g_random_int_range (0, 256);
  for (i = 0; i < sizeof iv; i++)
    iv[i] = (guint8) g_random_int_range (0, 256);

  cs = CCKeyDerivationPBKDF (kCCPBKDF2, password, strlen (password),
                             salt, sizeof salt, kCCPRFHmacAlgSHA256,
                             iterations, derived, key_len);
  if (cs != kCCSuccess)
    return NULL;

  ciphertext_cap = pkcs8_len + 16;
  ciphertext = g_malloc (ciphertext_cap);
  cs = CCCrypt (kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                derived, key_len, iv,
                pkcs8, pkcs8_len,
                ciphertext, ciphertext_cap, &produced);
  if (cs != kCCSuccess)
    {
      g_free (ciphertext);
      return NULL;
    }

  kdf_params = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    GByteArray *prf_algid = g_byte_array_new ();
    GByteArray *prf_algid_body = g_byte_array_new ();

    der_append_octet_string (inner, salt, sizeof salt);
    der_append_integer_uint (inner, iterations);

    der_append_oid (prf_algid_body, oid_hmac_sha256, sizeof oid_hmac_sha256);
    der_append_null (prf_algid_body);
    der_append_sequence (prf_algid, prf_algid_body->data, prf_algid_body->len);
    g_byte_array_unref (prf_algid_body);

    g_byte_array_append (inner, prf_algid->data, prf_algid->len);
    g_byte_array_unref (prf_algid);

    der_append_sequence (kdf_params, inner->data, inner->len);
    g_byte_array_unref (inner);
  }

  kdf_algid = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    der_append_oid (inner, oid_pbkdf2, sizeof oid_pbkdf2);
    g_byte_array_append (inner, kdf_params->data, kdf_params->len);
    der_append_sequence (kdf_algid, inner->data, inner->len);
    g_byte_array_unref (inner);
  }
  g_byte_array_unref (kdf_params);

  enc_algid = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    der_append_oid (inner, oid_aes256_cbc, sizeof oid_aes256_cbc);
    der_append_octet_string (inner, iv, iv_len);
    der_append_sequence (enc_algid, inner->data, inner->len);
    g_byte_array_unref (inner);
  }

  pbes2_params = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    g_byte_array_append (inner, kdf_algid->data, kdf_algid->len);
    g_byte_array_append (inner, enc_algid->data, enc_algid->len);
    der_append_sequence (pbes2_params, inner->data, inner->len);
    g_byte_array_unref (inner);
  }
  g_byte_array_unref (kdf_algid);
  g_byte_array_unref (enc_algid);

  pbes2_algid = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    der_append_oid (inner, oid_pbes2, sizeof oid_pbes2);
    g_byte_array_append (inner, pbes2_params->data, pbes2_params->len);
    der_append_sequence (pbes2_algid, inner->data, inner->len);
    g_byte_array_unref (inner);
  }
  g_byte_array_unref (pbes2_params);

  encrypted = g_byte_array_new ();
  {
    GByteArray *inner = g_byte_array_new ();
    g_byte_array_append (inner, pbes2_algid->data, pbes2_algid->len);
    der_append_octet_string (inner, ciphertext, produced);
    der_append_sequence (encrypted, inner->data, inner->len);
    g_byte_array_unref (inner);
  }
  g_byte_array_unref (pbes2_algid);
  g_free (ciphertext);

  return encrypted;
}

static void
pkcs12_kdf (const gchar  *password,
            const guint8 *salt,
            gsize         salt_len,
            guint         iterations,
            guint8        id,
            guint8       *out,
            gsize         out_len)
{
  const gsize v = 64;
  const gsize u = CC_SHA256_DIGEST_LENGTH;
  gunichar2 *utf16;
  glong utf16_len;
  guint8 *password_bmp;
  gsize password_bmp_len;
  gsize s_blocks, p_blocks, S_len, P_len, I_len;
  guint8 D[64];
  guint8 *S;
  guint8 *P;
  guint8 *I;
  guint8 A[CC_SHA256_DIGEST_LENGTH];
  gsize remaining = out_len;
  guint i;
  glong k;

  memset (D, id, v);

  utf16 = g_utf8_to_utf16 (password, -1, NULL, &utf16_len, NULL);
  password_bmp_len = ((gsize) utf16_len + 1) * 2;
  password_bmp = g_malloc (password_bmp_len);
  for (k = 0; k < utf16_len; k++)
    {
      password_bmp[k * 2 + 0] = (guint8) ((utf16[k] >> 8) & 0xff);
      password_bmp[k * 2 + 1] = (guint8) (utf16[k] & 0xff);
    }
  password_bmp[utf16_len * 2 + 0] = 0;
  password_bmp[utf16_len * 2 + 1] = 0;
  g_free (utf16);

  s_blocks = (salt_len + v - 1) / v;
  S_len = s_blocks * v;
  S = g_malloc (S_len);
  for (gsize j = 0; j < S_len; j++)
    S[j] = salt[j % salt_len];

  p_blocks = (password_bmp_len + v - 1) / v;
  P_len = p_blocks * v;
  P = g_malloc (P_len);
  for (gsize j = 0; j < P_len; j++)
    P[j] = password_bmp[j % password_bmp_len];

  I_len = S_len + P_len;
  I = g_malloc (I_len);
  memcpy (I, S, S_len);
  memcpy (I + S_len, P, P_len);
  g_free (S);
  g_free (P);
  g_free (password_bmp);

  while (remaining > 0)
    {
      gsize chunk;
      guint8 B[64];

      {
        guint8 *block = g_malloc (v + I_len);
        memcpy (block, D, v);
        memcpy (block + v, I, I_len);
        CC_SHA256 (block, (CC_LONG) (v + I_len), A);
        g_free (block);
      }
      for (i = 1; i < iterations; i++)
        CC_SHA256 (A, u, A);

      chunk = MIN (remaining, u);
      memcpy (out, A, chunk);
      out += chunk;
      remaining -= chunk;

      if (remaining == 0)
        break;

      for (gsize j = 0; j < v; j++)
        B[j] = A[j % u];

      for (gsize j = 0; j < I_len; j += v)
        {
          guint carry = 1;
          for (gint w = v - 1; w >= 0; w--)
            {
              guint sum = (guint) I[j + w] + (guint) B[w] + carry;
              I[j + w] = (guint8) (sum & 0xff);
              carry = sum >> 8;
            }
        }
    }

  g_free (I);
}

gboolean
g_tls_certificate_apple_matches_identity (GTlsCertificateApple *self,
                                          GSocketConnectable   *identity)
{
  const gchar *hostname = NULL;
  GInetAddress *ip = NULL;
  GPtrArray *dns_names;
  GPtrArray *ip_addresses;
  gboolean matched = FALSE;
  guint i;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_APPLE (self), FALSE);

  if (G_IS_NETWORK_ADDRESS (identity))
    {
      hostname = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
      ip = g_inet_address_new_from_string (hostname);
      if (ip)
        hostname = NULL;
    }
  else if (G_IS_NETWORK_SERVICE (identity))
    {
      hostname = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
    }
  else if (G_IS_INET_SOCKET_ADDRESS (identity))
    {
      ip = g_object_ref (g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (identity)));
    }
  else
    {
      return FALSE;
    }

  if (ip)
    {
      ip_addresses = certificate_san_ip_addresses (self->cert);
      if (ip_addresses)
        {
          for (i = 0; i < ip_addresses->len && !matched; i++)
            {
              GInetAddress *san = g_ptr_array_index (ip_addresses, i);
              if (g_inet_address_equal (ip, san))
                matched = TRUE;
            }
          g_ptr_array_unref (ip_addresses);
        }
      g_object_unref (ip);
      return matched;
    }

  dns_names = certificate_san_dns_names (self->cert);
  if (dns_names)
    {
      for (i = 0; i < dns_names->len && !matched; i++)
        {
          GBytes *entry = g_ptr_array_index (dns_names, i);
          gsize pattern_len;
          const gchar *pattern = g_bytes_get_data (entry, &pattern_len);

          if (pattern_len > 2 && pattern[0] == '*' && pattern[1] == '.')
            {
              const gchar *dot = strchr (hostname, '.');
              if (dot != NULL &&
                  strlen (dot + 1) == pattern_len - 2 &&
                  g_ascii_strncasecmp (dot + 1, pattern + 2, pattern_len - 2) == 0)
                matched = TRUE;
            }
          else if (pattern_len == strlen (hostname) &&
                   g_ascii_strncasecmp (hostname, pattern, pattern_len) == 0)
            {
              matched = TRUE;
            }
        }
      g_ptr_array_unref (dns_names);
      return matched;
    }

  {
    gchar *cn = certificate_subject_cn (self->cert);
    if (cn)
      {
        matched = g_ascii_strcasecmp (cn, hostname) == 0;
        g_free (cn);
      }
  }
  return matched;
}

CFDataRef
g_tls_certificate_apple_copy_raw_issuer_dn (SecCertificateRef cert)
{
  return copy_raw_tbs_name (cert, FALSE);
}

CFDataRef
g_tls_certificate_apple_copy_raw_subject_dn (SecCertificateRef cert)
{
  return copy_raw_tbs_name (cert, TRUE);
}

static CFDataRef
copy_raw_tbs_name (SecCertificateRef cert,
                   gboolean          want_subject)
{
  CFDataRef result = NULL;
  CFDataRef der;
  const guint8 *body, *tbs, *cursor, *skip_body;
  gsize body_len, tbs_len, remaining, skip_len, total;
  guint8 tag;

  if (!cert)
    return NULL;

  der = SecCertificateCopyData (cert);
  if (!der)
    return NULL;

  if (!asn1_read_tlv (CFDataGetBytePtr (der), CFDataGetLength (der),
                      &tag, &body, &body_len, &total) || tag != 0x30)
    goto out;

  if (!asn1_read_tlv (body, body_len, &tag, &tbs, &tbs_len, &total) || tag != 0x30)
    goto out;

  cursor = tbs;
  remaining = tbs_len;

  if (remaining >= 1 && cursor[0] == 0xa0)
    {
      if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total))
        goto out;
      cursor += total;
      remaining -= total;
    }

  if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total) || tag != 0x02)
    goto out;
  cursor += total;
  remaining -= total;

  if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total) || tag != 0x30)
    goto out;
  cursor += total;
  remaining -= total;

  if (want_subject)
    {
      if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total) || tag != 0x30)
        goto out;
      cursor += total;
      remaining -= total;

      if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total) || tag != 0x30)
        goto out;
      cursor += total;
      remaining -= total;
    }

  if (!asn1_read_tlv (cursor, remaining, &tag, &skip_body, &skip_len, &total) || tag != 0x30)
    goto out;
  result = CFDataCreate (kCFAllocatorDefault, cursor, total);

out:
  CFRelease (der);
  return result;
}

static gchar *
certificate_subject_cn (SecCertificateRef cert)
{
  gchar *result;
  CFDataRef der;

  der = SecCertificateCopyNormalizedSubjectSequence (cert);
  if (!der)
    return NULL;

  result = x500_name_cn (CFDataGetBytePtr (der), CFDataGetLength (der));
  CFRelease (der);
  return result;
}

static gchar *
x500_name_cn (const guint8 *der,
              gsize         len)
{
  static const guint8 OID_CN[] = { 0x55, 0x04, 0x03 };
  guint8 tag;
  const guint8 *seq_body;
  gsize seq_len, total, cursor;

  if (!asn1_read_tlv (der, len, &tag, &seq_body, &seq_len, &total) || tag != 0x30)
    return NULL;

  cursor = 0;
  while (cursor < seq_len)
    {
      const guint8 *rdn_body;
      gsize rdn_len, inner_cursor = 0;

      if (!asn1_read_tlv (seq_body + cursor, seq_len - cursor,
                          &tag, &rdn_body, &rdn_len, &total) || tag != 0x31)
        return NULL;
      cursor += total;

      while (inner_cursor < rdn_len)
        {
          const guint8 *atv_body, *oid_body, *val_body;
          gsize atv_len, atv_total, oid_len, oid_total, val_len;

          if (!asn1_read_tlv (rdn_body + inner_cursor, rdn_len - inner_cursor,
                              &tag, &atv_body, &atv_len, &atv_total) || tag != 0x30)
            return NULL;
          inner_cursor += atv_total;

          if (!asn1_read_tlv (atv_body, atv_len, &tag, &oid_body, &oid_len, &oid_total) || tag != 0x06)
            continue;

          if (oid_len == sizeof OID_CN && memcmp (oid_body, OID_CN, oid_len) == 0)
            {
              if (!asn1_read_tlv (atv_body + oid_total, atv_len - oid_total,
                                  &tag, &val_body, &val_len, &total))
                return NULL;
              return g_strndup ((const gchar *) val_body, val_len);
            }
        }
    }
  return NULL;
}
