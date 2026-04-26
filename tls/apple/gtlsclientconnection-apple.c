/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsclientconnection-apple.c
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

#include "gtlsclientconnection-apple.h"
#include "gtlscertificate-apple.h"
#include <glib/gi18n-lib.h>

#ifndef GIO_APPLE_PUBLIC_API_ONLY
extern nw_connection_t nw_connection_create_with_connected_socket_and_parameters (int fd, nw_parameters_t parameters);
extern void            nw_parameters_set_allow_joining_connected_fd (nw_parameters_t parameters, bool allow);
#endif

struct _GTlsClientConnectionApple
{
  GTlsConnectionApple parent_instance;

  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;
  GList *accepted_cas;
  gchar **alpn_protocols;
};

enum {
  PROP_0,
  PROP_VALIDATION_FLAGS,
  PROP_SERVER_IDENTITY,
  PROP_USE_SSL3,
  PROP_ACCEPTED_CAS,
};

static void     g_tls_client_connection_apple_dispose              (GObject *object);
static void     g_tls_client_connection_apple_finalize             (GObject *object);
static void     g_tls_client_connection_apple_get_property         (GObject    *object,
                                                                    guint       prop_id,
                                                                    GValue     *value,
                                                                    GParamSpec *pspec);
static void     g_tls_client_connection_apple_set_property         (GObject      *object,
                                                                    guint         prop_id,
                                                                    const GValue *value,
                                                                    GParamSpec   *pspec);
static gboolean g_tls_client_connection_apple_start_handshake      (GTlsConnectionApple *base_self,
                                                                    GError             **error);
static gboolean g_tls_client_connection_apple_initable_init        (GInitable     *initable,
                                                                    GCancellable  *cancellable,
                                                                    GError       **error);
static void     g_tls_client_connection_apple_client_interface_init (GTlsClientConnectionInterface *iface);
static void     g_tls_client_connection_apple_dtls_iface_init      (GDtlsClientConnectionInterface *iface);
static void     g_tls_client_connection_apple_initable_iface_init  (GInitableIface                *iface);

static void           apply_tls_options                     (GTlsClientConnectionApple *self,
                                                             sec_protocol_options_t     options);
static void           install_client_challenge_block        (GTlsClientConnectionApple *self,
                                                             sec_protocol_options_t     options);
static void           capture_accepted_cas_from_metadata    (GTlsClientConnectionApple *self,
                                                             sec_protocol_metadata_t    metadata);
static sec_identity_t copy_local_sec_identity               (GTlsClientConnectionApple *self);

G_DEFINE_TYPE_WITH_CODE (GTlsClientConnectionApple, g_tls_client_connection_apple,
                         G_TYPE_TLS_CONNECTION_APPLE,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_apple_client_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_apple_dtls_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_client_connection_apple_initable_iface_init))

static void
g_tls_client_connection_apple_class_init (GTlsClientConnectionAppleClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GTlsConnectionAppleClass *apple_class = (GTlsConnectionAppleClass *) klass;

  object_class->dispose      = g_tls_client_connection_apple_dispose;
  object_class->finalize     = g_tls_client_connection_apple_finalize;
  object_class->get_property = g_tls_client_connection_apple_get_property;
  object_class->set_property = g_tls_client_connection_apple_set_property;

  apple_class->start_handshake = g_tls_client_connection_apple_start_handshake;

  g_object_class_override_property (object_class, PROP_VALIDATION_FLAGS, "validation-flags");
  g_object_class_override_property (object_class, PROP_SERVER_IDENTITY,  "server-identity");
  g_object_class_override_property (object_class, PROP_USE_SSL3,         "use-ssl3");
  g_object_class_override_property (object_class, PROP_ACCEPTED_CAS,     "accepted-cas");
}

static void
g_tls_client_connection_apple_init (GTlsClientConnectionApple *self)
{
}

static void
g_tls_client_connection_apple_dispose (GObject *object)
{
  GTlsClientConnectionApple *self = G_TLS_CLIENT_CONNECTION_APPLE (object);

  g_list_free_full (g_steal_pointer (&self->accepted_cas), (GDestroyNotify) g_byte_array_unref);
  g_clear_object (&self->server_identity);

  G_OBJECT_CLASS (g_tls_client_connection_apple_parent_class)->dispose (object);
}

static void
g_tls_client_connection_apple_finalize (GObject *object)
{
  GTlsClientConnectionApple *self = G_TLS_CLIENT_CONNECTION_APPLE (object);

  g_strfreev (self->alpn_protocols);

  G_OBJECT_CLASS (g_tls_client_connection_apple_parent_class)->finalize (object);
}

static void
g_tls_client_connection_apple_get_property (GObject    *object,
                                            guint       prop_id,
                                            GValue     *value,
                                            GParamSpec *pspec)
{
  GTlsClientConnectionApple *self = G_TLS_CLIENT_CONNECTION_APPLE (object);

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, self->validation_flags);
      break;
    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, self->server_identity);
      break;
    case PROP_USE_SSL3:
      g_value_set_boolean (value, self->use_ssl3);
      break;
    case PROP_ACCEPTED_CAS:
      g_value_set_pointer (value, self->accepted_cas);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_apple_set_property (GObject      *object,
                                            guint         prop_id,
                                            const GValue *value,
                                            GParamSpec   *pspec)
{
  GTlsClientConnectionApple *self = G_TLS_CLIENT_CONNECTION_APPLE (object);

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      self->validation_flags = g_value_get_flags (value);
      break;
    case PROP_SERVER_IDENTITY:
      g_clear_object (&self->server_identity);
      self->server_identity = g_value_dup_object (value);
      break;
    case PROP_USE_SSL3:
      self->use_ssl3 = g_value_get_boolean (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gboolean
g_tls_client_connection_apple_start_handshake (GTlsConnectionApple  *base_self,
                                               GError              **error)
{
  GTlsClientConnectionApple *self = G_TLS_CLIENT_CONNECTION_APPLE (base_self);
  gboolean is_dtls = g_tls_connection_base_is_dtls (G_TLS_CONNECTION_BASE (self));
  nw_parameters_configure_protocol_block_t configure_sec =
      ^(nw_protocol_options_t proto_options) {
        sec_protocol_options_t sec_opts = nw_tls_copy_sec_protocol_options (proto_options);
        apply_tls_options (self, sec_opts);
        nw_release (sec_opts);
      };
#ifdef GIO_APPLE_PUBLIC_API_ONLY
  nw_parameters_configure_protocol_block_t configure_tcp =
      ^(nw_protocol_options_t tcp_options) {
        nw_tcp_options_set_no_delay (tcp_options, true);
      };
#else
  nw_parameters_configure_protocol_block_t configure_tcp = NW_PARAMETERS_DEFAULT_CONFIGURATION;
#endif
  nw_parameters_t parameters = is_dtls
      ? nw_parameters_create_secure_udp (configure_sec, NW_PARAMETERS_DEFAULT_CONFIGURATION)
      : nw_parameters_create_secure_tcp (configure_sec, configure_tcp);
  nw_connection_t connection;

#ifdef GIO_APPLE_PUBLIC_API_ONLY
  guint16 apple_port;
  gchar port_str[8];
  nw_endpoint_t endpoint;

  if (!g_tls_connection_apple_setup_public_endpoint (base_self, &apple_port, error))
    {
      nw_release (parameters);
      return FALSE;
    }

  g_snprintf (port_str, sizeof port_str, "%u", apple_port);
  endpoint = nw_endpoint_create_host ("127.0.0.1", port_str);

  connection = nw_connection_create (endpoint, parameters);
  nw_release (endpoint);
  nw_release (parameters);

  if (connection == NULL)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("nw_connection_create returned NULL"));
      return FALSE;
    }
#else
  int apple_fd;

  nw_parameters_set_allow_joining_connected_fd (parameters, true);

  apple_fd = g_tls_connection_apple_setup_bounce_transport (base_self, error);
  if (apple_fd < 0)
    {
      nw_release (parameters);
      return FALSE;
    }

  connection = nw_connection_create_with_connected_socket_and_parameters (apple_fd, parameters);
  nw_release (parameters);

  if (connection == NULL)
    {
      g_tls_connection_apple_release_bounce_fd (base_self, apple_fd);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("nw_connection_create_with_connected_socket_and_parameters returned NULL"));
      return FALSE;
    }
#endif

  g_tls_connection_apple_attach (base_self, connection);
  nw_release (connection);

  return TRUE;
}

static void
apply_tls_options (GTlsClientConnectionApple *self,
                   sec_protocol_options_t     options)
{
  const gchar *server_name = NULL;
  tls_protocol_version_t min_version;

  if (G_IS_NETWORK_ADDRESS (self->server_identity))
    server_name = g_network_address_get_hostname (G_NETWORK_ADDRESS (self->server_identity));
  else if (G_IS_NETWORK_SERVICE (self->server_identity))
    server_name = g_network_service_get_domain (G_NETWORK_SERVICE (self->server_identity));

  if (server_name != NULL)
    sec_protocol_options_set_tls_server_name (options, server_name);

  min_version = g_tls_connection_base_is_dtls (G_TLS_CONNECTION_BASE (self))
      ? tls_protocol_version_DTLSv12
      : tls_protocol_version_TLSv12;
  sec_protocol_options_set_min_tls_protocol_version (options, min_version);

  g_tls_connection_apple_add_advertised_protocols (G_TLS_CONNECTION (self), options);

  install_client_challenge_block (self, options);
  g_tls_connection_apple_install_verify_block (G_TLS_CONNECTION_APPLE (self), options);
}

static void
install_client_challenge_block (GTlsClientConnectionApple *self,
                                sec_protocol_options_t     options)
{
  GWeakRef *weak_self =
      g_tls_connection_apple_get_weak_self (G_TLS_CONNECTION_APPLE (self));

  sec_protocol_options_set_challenge_block (options,
      ^(sec_protocol_metadata_t metadata,
        sec_protocol_challenge_complete_t complete) {
        GTlsClientConnectionApple *strong_self = g_weak_ref_get (weak_self);
        sec_identity_t identity = NULL;

        if (strong_self != NULL)
          {
            capture_accepted_cas_from_metadata (strong_self, metadata);
            identity = copy_local_sec_identity (strong_self);
            g_object_unref (strong_self);
          }

        complete (identity);
        g_clear_pointer (&identity, nw_release);
      },
      g_tls_connection_apple_get_queue (G_TLS_CONNECTION_APPLE (self)));
}

static void
capture_accepted_cas_from_metadata (GTlsClientConnectionApple *self,
                                    sec_protocol_metadata_t    metadata)
{
  __block GList *cas = NULL;

  sec_protocol_metadata_access_distinguished_names (metadata,
      ^(dispatch_data_t name_data) {
        GByteArray *ba = g_byte_array_new ();
        dispatch_data_apply (name_data,
            ^bool (dispatch_data_t region, size_t offset, const void *bytes, size_t size) {
              g_byte_array_append (ba, bytes, size);
              return true;
            });
        cas = g_list_prepend (cas, ba);
      });
  cas = g_list_reverse (cas);

  g_list_free_full (self->accepted_cas, (GDestroyNotify) g_byte_array_unref);
  self->accepted_cas = cas;
  g_object_notify (G_OBJECT (self), "accepted-cas");
}

static sec_identity_t
copy_local_sec_identity (GTlsClientConnectionApple *self)
{
  sec_identity_t sec_identity = NULL;
  GTlsCertificate *local_cert;
  SecIdentityRef identity;

  local_cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (self));
  if (!G_IS_TLS_CERTIFICATE_APPLE (local_cert))
    {
      if (g_tls_connection_base_handshake_thread_request_certificate (G_TLS_CONNECTION_BASE (self)))
        local_cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (self));
    }

  if (!G_IS_TLS_CERTIFICATE_APPLE (local_cert))
    return NULL;

  identity = g_tls_certificate_apple_copy_identity (G_TLS_CERTIFICATE_APPLE (local_cert));
  if (identity)
    {
      sec_identity = sec_identity_create (identity);
      CFRelease (identity);
    }
  return sec_identity;
}

static void
g_tls_client_connection_apple_client_interface_init (GTlsClientConnectionInterface *iface)
{
  iface->copy_session_state = NULL;
}

static void
g_tls_client_connection_apple_dtls_iface_init (GDtlsClientConnectionInterface *iface)
{
}

static void
g_tls_client_connection_apple_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_client_connection_apple_initable_init;
}

static gboolean
g_tls_client_connection_apple_initable_init (GInitable     *initable,
                                             GCancellable  *cancellable,
                                             GError       **error)
{
  GTlsConnectionBase *tls_base = G_TLS_CONNECTION_BASE (initable);
  GTlsConnectionApple *base_self = G_TLS_CONNECTION_APPLE (initable);

  if (g_tls_connection_base_is_dtls (tls_base))
    return g_tls_connection_apple_bind_base_socket (base_self,
        g_tls_connection_base_get_base_socket (tls_base), error);

  return g_tls_connection_apple_bind_base_iostream (base_self,
      g_tls_connection_base_get_base_iostream (tls_base), error);
}
