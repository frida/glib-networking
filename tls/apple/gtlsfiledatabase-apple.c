/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsfiledatabase-apple.c
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

#include "gtlsfiledatabase-apple.h"
#include "gtlscertificate-apple.h"

#include <glib/gi18n-lib.h>

struct _GTlsFileDatabaseApple
{
  GTlsDatabaseApple parent_instance;

  gchar *anchor_filename;
};

enum {
  PROP_0,
  PROP_ANCHORS,
};

static void     g_tls_file_database_apple_finalize                  (GObject *object);
static void     g_tls_file_database_apple_get_property              (GObject    *object,
                                                                     guint       prop_id,
                                                                     GValue     *value,
                                                                     GParamSpec *pspec);
static void     g_tls_file_database_apple_set_property              (GObject      *object,
                                                                     guint         prop_id,
                                                                     const GValue *value,
                                                                     GParamSpec   *pspec);
static gchar           *g_tls_file_database_apple_create_certificate_handle (GTlsDatabase    *database,
                                                                             GTlsCertificate *certificate);
static GTlsCertificate *g_tls_file_database_apple_lookup_certificate_for_handle (GTlsDatabase            *database,
                                                                                 const gchar             *handle,
                                                                                 GTlsInteraction         *interaction,
                                                                                 GTlsDatabaseLookupFlags  flags,
                                                                                 GCancellable            *cancellable,
                                                                                 GError                 **error);
static GTlsCertificate *g_tls_file_database_apple_lookup_certificate_issuer     (GTlsDatabase             *database,
                                                                                 GTlsCertificate          *certificate,
                                                                                 GTlsInteraction          *interaction,
                                                                                 GTlsDatabaseLookupFlags   flags,
                                                                                 GCancellable             *cancellable,
                                                                                 GError                  **error);
static GList           *g_tls_file_database_apple_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                                                 GByteArray               *issuer_raw_dn,
                                                                                 GTlsInteraction          *interaction,
                                                                                 GTlsDatabaseLookupFlags   flags,
                                                                                 GCancellable             *cancellable,
                                                                                 GError                  **error);
static void     g_tls_file_database_apple_file_database_iface_init  (GTlsFileDatabaseInterface *iface);
static void     g_tls_file_database_apple_initable_iface_init       (GInitableIface            *iface);
static gboolean g_tls_file_database_apple_initable_init             (GInitable     *initable,
                                                                     GCancellable  *cancellable,
                                                                     GError       **error);

static gboolean          load_anchor_bundle_into_database (GTlsDatabaseApple *database,
                                                           const gchar       *filename,
                                                           GError           **error);
static CFMutableArrayRef parse_pem_bundle_to_cert_array   (const gchar       *pem,
                                                           gsize              len);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseApple, g_tls_file_database_apple, G_TYPE_TLS_DATABASE_APPLE,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_apple_file_database_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_file_database_apple_initable_iface_init))

static void
g_tls_file_database_apple_class_init (GTlsFileDatabaseAppleClass *klass)
{
  GObjectClass      *object_class   = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  object_class->finalize     = g_tls_file_database_apple_finalize;
  object_class->get_property = g_tls_file_database_apple_get_property;
  object_class->set_property = g_tls_file_database_apple_set_property;

  database_class->create_certificate_handle      = g_tls_file_database_apple_create_certificate_handle;
  database_class->lookup_certificate_for_handle  = g_tls_file_database_apple_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer      = g_tls_file_database_apple_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by  = g_tls_file_database_apple_lookup_certificates_issued_by;

  g_object_class_override_property (object_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_apple_init (GTlsFileDatabaseApple *self)
{
}

static void
g_tls_file_database_apple_finalize (GObject *object)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (object);

  g_free (self->anchor_filename);

  G_OBJECT_CLASS (g_tls_file_database_apple_parent_class)->finalize (object);
}

static void
g_tls_file_database_apple_get_property (GObject    *object,
                                        guint       prop_id,
                                        GValue     *value,
                                        GParamSpec *pspec)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (object);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      g_value_set_string (value, self->anchor_filename);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_apple_set_property (GObject      *object,
                                        guint         prop_id,
                                        const GValue *value,
                                        GParamSpec   *pspec)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (object);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      g_free (self->anchor_filename);
      self->anchor_filename = g_value_dup_string (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gchar *
g_tls_file_database_apple_create_certificate_handle (GTlsDatabase    *database,
                                                     GTlsCertificate *certificate)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (database);
  GTlsDatabaseApple *base = G_TLS_DATABASE_APPLE (database);
  gchar *handle = NULL;
  SecCertificateRef target;
  CFDataRef target_der;
  CFIndex i;
  gboolean contains = FALSE;
  gchar *uri = NULL;
  gchar *checksum = NULL;

  if (!G_IS_TLS_CERTIFICATE_APPLE (certificate) ||
      self->anchor_filename == NULL ||
      base->anchors == NULL)
    return NULL;

  target = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (certificate));
  if (!target)
    return NULL;

  target_der = SecCertificateCopyData (target);
  if (!target_der)
    return NULL;

  for (i = 0; !contains && i < CFArrayGetCount (base->anchors); i++)
    {
      SecCertificateRef anchor = (SecCertificateRef) CFArrayGetValueAtIndex (base->anchors, i);
      CFDataRef der = SecCertificateCopyData (anchor);

      if (der && CFEqual (der, target_der))
        contains = TRUE;

      g_clear_pointer (&der, CFRelease);
    }

  if (!contains)
    goto out;

  uri = g_filename_to_uri (self->anchor_filename, NULL, NULL);
  checksum = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
                                          CFDataGetBytePtr (target_der),
                                          CFDataGetLength (target_der));
  if (uri && checksum)
    handle = g_strconcat (uri, "#", checksum, NULL);

out:
  g_free (uri);
  g_free (checksum);
  CFRelease (target_der);
  return handle;
}

static GTlsCertificate *
g_tls_file_database_apple_lookup_certificate_for_handle (GTlsDatabase            *database,
                                                         const gchar             *handle,
                                                         GTlsInteraction         *interaction,
                                                         GTlsDatabaseLookupFlags  flags,
                                                         GCancellable            *cancellable,
                                                         GError                 **error)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (database);
  GTlsDatabaseApple *base = G_TLS_DATABASE_APPLE (database);
  GTlsCertificate *result = NULL;
  const gchar *fragment;
  gchar *uri_part;
  gchar *expected_uri;
  gboolean uri_matches;
  CFIndex i;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  if (handle == NULL || self->anchor_filename == NULL || base->anchors == NULL)
    return NULL;

  fragment = strchr (handle, '#');
  if (!fragment)
    return NULL;

  uri_part = g_strndup (handle, fragment - handle);
  fragment += 1;

  expected_uri = g_filename_to_uri (self->anchor_filename, NULL, NULL);
  uri_matches = expected_uri != NULL && g_strcmp0 (uri_part, expected_uri) == 0;

  g_free (uri_part);
  g_free (expected_uri);

  if (!uri_matches)
    return NULL;

  for (i = 0; i < CFArrayGetCount (base->anchors); i++)
    {
      SecCertificateRef anchor = (SecCertificateRef) CFArrayGetValueAtIndex (base->anchors, i);
      CFDataRef der = SecCertificateCopyData (anchor);
      gchar *checksum;

      if (!der)
        continue;

      checksum = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
                                              CFDataGetBytePtr (der),
                                              CFDataGetLength (der));
      CFRelease (der);

      if (checksum && g_strcmp0 (checksum, fragment) == 0)
        {
          result = g_tls_certificate_apple_new_from_sec (anchor, NULL, NULL);
          g_free (checksum);
          break;
        }

      g_free (checksum);
    }

  return result;
}

static GTlsCertificate *
g_tls_file_database_apple_lookup_certificate_issuer (GTlsDatabase             *database,
                                                     GTlsCertificate          *certificate,
                                                     GTlsInteraction          *interaction,
                                                     GTlsDatabaseLookupFlags   flags,
                                                     GCancellable             *cancellable,
                                                     GError                  **error)
{
  GTlsDatabaseApple *base = G_TLS_DATABASE_APPLE (database);
  GTlsCertificate *result = NULL;
  SecCertificateRef leaf;
  CFDataRef target;
  CFIndex i;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_APPLE (certificate), NULL);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  if (base->anchors == NULL)
    return NULL;

  leaf = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (certificate));
  if (!leaf)
    return NULL;

  target = g_tls_certificate_apple_copy_raw_issuer_dn (leaf);
  if (!target)
    return NULL;

  for (i = 0; i < CFArrayGetCount (base->anchors); i++)
    {
      SecCertificateRef anchor = (SecCertificateRef) CFArrayGetValueAtIndex (base->anchors, i);
      CFDataRef subject = g_tls_certificate_apple_copy_raw_subject_dn (anchor);

      if (subject && CFEqual (subject, target))
        result = g_tls_certificate_apple_new_from_sec (anchor, NULL, NULL);

      g_clear_pointer (&subject, CFRelease);

      if (result)
        break;
    }

  CFRelease (target);
  return result;
}

static GList *
g_tls_file_database_apple_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                         GByteArray               *issuer_raw_dn,
                                                         GTlsInteraction          *interaction,
                                                         GTlsDatabaseLookupFlags   flags,
                                                         GCancellable             *cancellable,
                                                         GError                  **error)
{
  GTlsDatabaseApple *base = G_TLS_DATABASE_APPLE (database);
  GList *result = NULL;
  CFDataRef target;
  CFIndex i;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  if (base->anchors == NULL)
    return NULL;

  target = CFDataCreate (kCFAllocatorDefault, issuer_raw_dn->data, issuer_raw_dn->len);
  if (!target)
    return NULL;

  for (i = 0; i < CFArrayGetCount (base->anchors); i++)
    {
      SecCertificateRef anchor = (SecCertificateRef) CFArrayGetValueAtIndex (base->anchors, i);
      CFDataRef issuer = g_tls_certificate_apple_copy_raw_issuer_dn (anchor);

      if (issuer && CFEqual (issuer, target))
        {
          GTlsCertificate *wrapper = g_tls_certificate_apple_new_from_sec (anchor, NULL, NULL);
          if (wrapper)
            result = g_list_prepend (result, wrapper);
        }

      g_clear_pointer (&issuer, CFRelease);
    }

  CFRelease (target);
  return result;
}

static void
g_tls_file_database_apple_file_database_iface_init (GTlsFileDatabaseInterface *iface)
{
}

static void
g_tls_file_database_apple_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_file_database_apple_initable_init;
}

static gboolean
g_tls_file_database_apple_initable_init (GInitable     *initable,
                                         GCancellable  *cancellable,
                                         GError       **error)
{
  GTlsFileDatabaseApple *self = G_TLS_FILE_DATABASE_APPLE (initable);

  if (!self->anchor_filename)
    return TRUE;

  return load_anchor_bundle_into_database (G_TLS_DATABASE_APPLE (self),
                                           self->anchor_filename, error);
}

static gboolean
load_anchor_bundle_into_database (GTlsDatabaseApple *database,
                                  const gchar       *filename,
                                  GError           **error)
{
  gchar *contents;
  gsize length;
  CFMutableArrayRef anchors;

  if (!g_file_get_contents (filename, &contents, &length, error))
    return FALSE;

  anchors = parse_pem_bundle_to_cert_array (contents, length);
  g_free (contents);

  if (!anchors || CFArrayGetCount (anchors) == 0)
    {
      g_clear_pointer (&anchors, CFRelease);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("No certificates found in anchor bundle %s"), filename);
      return FALSE;
    }

  g_clear_pointer (&database->anchors, CFRelease);
  database->anchors = anchors;
  return TRUE;
}

static CFMutableArrayRef
parse_pem_bundle_to_cert_array (const gchar *pem,
                                gsize        len)
{
  CFMutableArrayRef result;
  const gchar *cursor = pem;
  const gchar *end = pem + len;

  result = CFArrayCreateMutable (kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);

  while (cursor < end)
    {
      const gchar *begin_marker = g_strstr_len (cursor, end - cursor, "-----BEGIN CERTIFICATE-----");
      const gchar *end_marker;
      const gchar *line_start;
      GString *b64;
      gchar *encoded;
      guchar *der;
      gsize der_len;
      CFDataRef data;
      SecCertificateRef cert;

      if (!begin_marker)
        break;

      line_start = strchr (begin_marker, '\n');
      if (!line_start)
        break;
      line_start += 1;

      end_marker = g_strstr_len (line_start, end - line_start, "-----END CERTIFICATE-----");
      if (!end_marker)
        break;

      b64 = g_string_new (NULL);
      {
        const gchar *p = line_start;
        while (p < end_marker)
          {
            const gchar *line_end = memchr (p, '\n', end_marker - p);
            if (!line_end)
              line_end = end_marker;
            if (line_end > p && line_end[-1] == '\r')
              g_string_append_len (b64, p, line_end - p - 1);
            else
              g_string_append_len (b64, p, line_end - p);
            if (line_end >= end_marker)
              break;
            p = line_end + 1;
          }
      }

      encoded = g_string_free (b64, FALSE);
      der = g_base64_decode (encoded, &der_len);
      g_free (encoded);

      if (der && der_len > 0)
        {
          data = CFDataCreate (kCFAllocatorDefault, der, der_len);
          cert = SecCertificateCreateWithData (kCFAllocatorDefault, data);
          CFRelease (data);

          if (cert)
            {
              CFArrayAppendValue (result, cert);
              CFRelease (cert);
            }
        }
      g_free (der);

      cursor = end_marker + strlen ("-----END CERTIFICATE-----");
    }

  return result;
}
