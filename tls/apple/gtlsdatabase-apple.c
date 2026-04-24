/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsdatabase-apple.c
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

#include "gtlsdatabase-apple.h"
#include "gtlscertificate-apple.h"

#include <glib/gi18n-lib.h>

static void                  g_tls_database_apple_dispose     (GObject *object);
static GTlsCertificateFlags  g_tls_database_apple_verify_chain (GTlsDatabase             *database,
                                                                GTlsCertificate          *chain,
                                                                const gchar              *purpose,
                                                                GSocketConnectable       *identity,
                                                                GTlsInteraction          *interaction,
                                                                GTlsDatabaseVerifyFlags   flags,
                                                                GCancellable             *cancellable,
                                                                GError                  **error);

static CFArrayRef           collect_chain           (GTlsCertificate          *chain);
static gboolean             certificate_is_self_issued (SecCertificateRef      cert);
static SecPolicyRef         policy_for_purpose      (const gchar              *purpose,
                                                     GSocketConnectable       *identity);
static GTlsCertificateFlags evaluate_trust          (SecTrustRef               trust,
                                                     GTlsDatabaseVerifyFlags   flags);
static GTlsCertificateFlags translate_cf_error      (CFErrorRef                error);
static gboolean             not_activated_in_leaf   (GTlsCertificate          *chain);

G_DEFINE_TYPE (GTlsDatabaseApple, g_tls_database_apple, G_TYPE_TLS_DATABASE)

static void
g_tls_database_apple_class_init (GTlsDatabaseAppleClass *klass)
{
  GObjectClass      *object_class   = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  object_class->dispose        = g_tls_database_apple_dispose;
  database_class->verify_chain = g_tls_database_apple_verify_chain;
}

static void
g_tls_database_apple_init (GTlsDatabaseApple *self)
{
  self->anchors = NULL;
}

static void
g_tls_database_apple_dispose (GObject *object)
{
  GTlsDatabaseApple *self = G_TLS_DATABASE_APPLE (object);

  g_clear_pointer (&self->anchors, CFRelease);

  G_OBJECT_CLASS (g_tls_database_apple_parent_class)->dispose (object);
}

static GTlsCertificateFlags
g_tls_database_apple_verify_chain (GTlsDatabase             *database,
                                   GTlsCertificate          *chain,
                                   const gchar              *purpose,
                                   GSocketConnectable       *identity,
                                   GTlsInteraction          *interaction,
                                   GTlsDatabaseVerifyFlags   flags,
                                   GCancellable             *cancellable,
                                   GError                  **error)
{
  GTlsDatabaseApple *self = G_TLS_DATABASE_APPLE (database);
  GTlsCertificateFlags result;
  CFArrayRef cert_chain;
  SecPolicyRef policy;
  OSStatus status;
  SecTrustRef trust = NULL;

  cert_chain = collect_chain (chain);
  if (!cert_chain)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  policy = policy_for_purpose (purpose, identity);
  if (!policy)
    {
      CFRelease (cert_chain);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  status = SecTrustCreateWithCertificates (cert_chain, policy, &trust);
  CFRelease (cert_chain);
  CFRelease (policy);

  if (status != errSecSuccess || !trust)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  if (self->anchors)
    {
      SecTrustSetAnchorCertificates (trust, self->anchors);
      SecTrustSetAnchorCertificatesOnly (trust, true);
    }

  result = evaluate_trust (trust, flags);
  CFRelease (trust);

  if (result == G_TLS_CERTIFICATE_EXPIRED && not_activated_in_leaf (chain))
    result = G_TLS_CERTIFICATE_NOT_ACTIVATED;

  if (identity && G_IS_TLS_CERTIFICATE_APPLE (chain) &&
      (purpose == NULL || g_strcmp0 (purpose, G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER) == 0))
    {
      if (!g_tls_certificate_apple_matches_identity (G_TLS_CERTIFICATE_APPLE (chain), identity))
        result |= G_TLS_CERTIFICATE_BAD_IDENTITY;
    }

  return result;
}

GTlsDatabaseApple *
g_tls_database_apple_new (GError **error)
{
  return g_object_new (G_TYPE_TLS_DATABASE_APPLE, NULL);
}

static CFArrayRef
collect_chain (GTlsCertificate *chain)
{
  CFMutableArrayRef array = CFArrayCreateMutable (kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  GTlsCertificate *cursor;
  CFIndex count;

  for (cursor = chain; cursor; cursor = g_tls_certificate_get_issuer (cursor))
    {
      SecCertificateRef cert;

      if (!G_IS_TLS_CERTIFICATE_APPLE (cursor))
        {
          CFRelease (array);
          return NULL;
        }

      cert = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (cursor));
      if (!cert)
        {
          CFRelease (array);
          return NULL;
        }

      CFArrayAppendValue (array, cert);
    }

  count = CFArrayGetCount (array);
  if (count > 1)
    {
      SecCertificateRef last = (SecCertificateRef) CFArrayGetValueAtIndex (array, count - 1);
      if (certificate_is_self_issued (last))
        CFArrayRemoveValueAtIndex (array, count - 1);
    }

  return array;
}

static gboolean
certificate_is_self_issued (SecCertificateRef cert)
{
  gboolean result = FALSE;
  CFDataRef subject;
  CFDataRef issuer;

  subject = SecCertificateCopyNormalizedSubjectSequence (cert);
  issuer = SecCertificateCopyNormalizedIssuerSequence (cert);
  if (subject && issuer)
    result = CFEqual (subject, issuer);

  g_clear_pointer (&subject, CFRelease);
  g_clear_pointer (&issuer, CFRelease);
  return result;
}

static SecPolicyRef
policy_for_purpose (const gchar        *purpose,
                    GSocketConnectable *identity)
{
  (void) purpose;
  (void) identity;
  return SecPolicyCreateBasicX509 ();
}

static GTlsCertificateFlags
evaluate_trust (SecTrustRef             trust,
                GTlsDatabaseVerifyFlags flags)
{
  GTlsCertificateFlags mapped;
  CFErrorRef cf_error = NULL;

  if (SecTrustEvaluateWithError (trust, &cf_error))
    return 0;

  mapped = translate_cf_error (cf_error);
  g_clear_pointer (&cf_error, CFRelease);
  return mapped;
}

static GTlsCertificateFlags
translate_cf_error (CFErrorRef error)
{
  CFIndex code;

  if (!error)
    return G_TLS_CERTIFICATE_UNKNOWN_CA;

  code = CFErrorGetCode (error);
  switch (code)
    {
    case errSecCertificateExpired:
      return G_TLS_CERTIFICATE_EXPIRED;
    case errSecCertificateNotValidYet:
      return G_TLS_CERTIFICATE_NOT_ACTIVATED;
    case errSecCertificateRevoked:
      return G_TLS_CERTIFICATE_INSECURE;
    default:
      return G_TLS_CERTIFICATE_UNKNOWN_CA;
    }
}

static gboolean
not_activated_in_leaf (GTlsCertificate *chain)
{
  gboolean in_future;
  GDateTime *not_before = NULL;
  GDateTime *now;

  if (!G_IS_TLS_CERTIFICATE (chain))
    return FALSE;

  g_object_get (chain, "not-valid-before", &not_before, NULL);
  if (!not_before)
    return FALSE;

  now = g_date_time_new_now_utc ();
  in_future = g_date_time_compare (not_before, now) > 0;

  g_date_time_unref (now);
  g_date_time_unref (not_before);
  return in_future;
}
